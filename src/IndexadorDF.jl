module IndexadorDF

using Taro
using PyCall
using ProgressMeter
using Pipe: @pipe
using Suppressor
using ArgParse
import JSON

elasticsearch = pyimport("elasticsearch")
helpers = pyimport("elasticsearch.helpers")


MAPPING = Dict(
    "mappings" => Dict(
        "properties" => Dict(
            "title" => Dict("type" => "text"),
            "file_name" => Dict("type" => "text"),
            "path" => Dict("type" => "keyword"),
            "tag" => Dict("type" => "keyword"),
            "date" => Dict("type" => "date"),
            "cve" => Dict("type" => "keyword"),
            "content" => Dict("type" => "text")
        )
    )
)

function match_on_keys(pattern, dict, keys, fallback)
    for key in keys
        value = get(dict, key, missing)
        if ismissing(value)
            continue
        end
        match_result = match(pattern, value)
        if isnothing(match_result)
            continue
        end
        return match_result
    end
    return match(pattern, fallback)
end

function find_cve(meta, text)
    pattern = r"(?:\(?CVE\)??: ?)([A-Z0-9]{5,14})(?:^|\s|$)"i
    match_result = match_on_keys(pattern, meta, ("Keyword", "meta:keyword", "pdf:docinfo:keywords"), text)
    if !(isnothing(match_result) || ismissing(match_result))
        return match_result[1]
    end
    return ""
end

function clean_text(meta, text)
    if get(meta, "dc:title", "") != "EXTRACTO SOCIETARIO ELECTRÓNICO"
        return @pipe text |> strip |> replace(_, r"(  )+" => " ") |> replace(_, r"(\n\n)+" => "\n")
    else
        return @pipe text |> strip |> replace(_, r"(  )+" => " ") |> replace(_, "\n" => "") |> replace(_, "\t" => " ")
    end
end

function extract_document(path, tag)
    local meta
    local text
    @suppress meta, text = Taro.extract(path)
    text = clean_text(meta, text)
    getm(key) = get(meta, key, nothing)
    cve = find_cve(meta, text)
    (ismissing(cve) || cve == "") && @warn "CVE not found in $path" meta
    document = Dict(
        "title" => something(getm("title"), ""),
        "file_name" => basename(path),
        "path" => relpath(path),
        "tag" => tag,
        "date" => something(getm("Creation-Date"), getm("date"), getm("created"), getm("meta:creation-date"), getm("pdf:docinfo:created"), ""),
        "cve" => find_cve(meta, text),
        "content" => text
    )
    return document
end

function extract_and_load_from_directory(es_client, index_name, path, tag; batch_size = 500, extract_only = false)
    files = readdir(path, sort = false, join = true)
    n_files = length(files)
    total_uploaded, total_failed = (0, 0)
    @info "Loading $(n_files) documents in batches of $(batch_size) documents."

    extraction_progress = Progress(n_files; desc = "Loading documents...", dt = 0.3, showspeed = true)

    for i = 1:batch_size:n_files
        files_batch = Iterators.take((@view files[i:end]), batch_size)
        if length(files_batch) == 0
            break
        end
        document_batch::Vector{Dict{AbstractString,Union{AbstractString, UInt, Bool, Dict{String,AbstractString}, Dict{String, String}}}} = []
        for file in files_batch
            document = extract_document(file, tag)
            if isnothing(document) || document["content"] == ""
                @info "Skipping $(file) because it seems empty."
                continue
            end
            push!(document_batch, Dict(
                "_id" => hash(basename(file)),
                "_index" => index_name,
                "_source" => document,
            ))
            next!(extraction_progress)
        end
        if !extract_only
            uploaded, failed = helpers.bulk(
                es_client,
                document_batch,
                index = index_name,
                stats_only = true
            )
            total_uploaded += uploaded
            total_failed += failed
        end
        if failed > 0.05 * batch_size
            @warn "Failed to upload $(failed) documents in batch $(i) of $(n_files) documents."
        end
        if total_failed > 30 && total_failed > 0.6 * (total_failed + total_uploaded)
            @error "Error rate is above tolerance. Found $(total_failed) errors out of $(total_uploaded + total_failed) documents."
            @error "Aborting..."
            exit(1)
        end
    end
    finish!(extraction_progress)
    @info "Loading finished: $(total_uploaded) documents uploaded, $(total_failed) documents failed."
    return total_uploaded, total_failed
end

function create_index_if_necessary(es, index_name)
    if !es.indices.exists(index = index_name)
        @info "Creating index $index_name..."
        try
            es.indices.create(index = index_name, body = PyDict(MAPPING))
        catch e
            @error "Error creating index" e
            exit(1)
        end
    end
end

function parse_commandline()
    s = ArgParseSettings()

    @add_arg_table s begin
        "index_name"
        help = "name of the ES index to use"
        required = true
        "directory"
        help = "directory to be loaded"
        required = true
        "--extract-only"
        help = "Only extract the documents"
        action = :store_true
        "--batch-size", "-b"
        help = "Batch size for loading"
        arg_type = Int
        default = 500
        "--scheme"
        help = "ElasticSearch Scheme"
        default = "http"
        "--host"
        help = "ElasticSearch Host"
        default = "localhost"
        "--port"
        help = "ElasticSearch Port"
        default = 9200
        "--user"
        help = "ElasticSearch User"
        default = "elastic"
        "--password"
        help = "ElasticSearch Password"
        default = "changeme"
        "--tag"
        help = "Tag to be used for the documents"
    end

    return parse_args(s)
end

function main()
    parsed_args = parse_commandline()
    parsed_args["extract-only"] && @info "Extract-only mode enabled."

    # Configuration
    index_name = parsed_args["index_name"]
    tag = get(parsed_args, "tag", nothing)
    if isnothing(tag)
        @warn "No tag specified. Using directory name as tag."
        tag = relpath(parsed_args["directory"])
    end

    # Tika Setup
    Taro.init()

    # ElasticSearch Setup
    host_uri = "$(parsed_args["scheme"])://$(parsed_args["user"]):$(parsed_args["password"])@$(parsed_args["host"]):$(parsed_args["port"])"
    es = elasticsearch.Elasticsearch([host_uri])
    if !es.ping()
        @error "Error while connecting to ElasticSearch at $(parsed_args["host"]):$(parsed_args["port"])"
        exit(1)
    else
        @info "Connected to ElasticSearch at $(parsed_args["host"]):$(parsed_args["port"])"
    end
    parsed_args["extract-only"] || create_index_if_necessary(es, index_name)

    # Extract the documents
    extract_and_load_from_directory(es, index_name, parsed_args["directory"], tag; batch_size = parsed_args["batch-size"], extract_only = parsed_args["extract-only"])
end

main()

end # module