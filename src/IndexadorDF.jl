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
            "path" => Dict("type" => "text"),
            "date" => Dict("type" => "date"),
            "cve" => Dict("type" => "text"),
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

function extract_document(path)
    local meta
    local text
    @suppress meta, text = Taro.extract(path)
    text = clean_text(meta, text)
    getm(key) = get(meta, key, nothing)
    cve = find_cve(meta, text)
    (ismissing(cve) || cve == "") && @warn "CVE not found in $path" meta
    document = Dict(
        "_id" => hash(basename(path)),
        "title" => something(getm("title"), ""),
        "file_name" => basename(path),
        "path" => relpath(path),
        "date" => something(getm("Creation-Date"), getm("date"), getm("created"), getm("meta:creation-date"), getm("pdf:docinfo:created"), ""),
        "cve" => find_cve(meta, text),
        "content" => text
    )
    return document
end

function extract_from_directory(path)
    documents::Vector{Dict{AbstractString,Union{AbstractString,Integer}}} = []
    files = readdir(path, sort = false, join = true)
    @info "Starting extractions of $(length(files)) documents."
    @showprogress 0.3 "Extracting texts..." for file in files
        document = extract_document(file)
        if isnothing(document) || document["content"] == ""
            @info "Skipping $(file) because it seems empty."
            continue
        end
        push!(documents, document)
    end
    @info "Text extraction finished."
    return documents
end

function load_in_batches(es_client, index_name, documents; batch_size = 500)
    @info "Loading $(length(documents)) documents in batches of $(batch_size) documents."
    @showprogress 0.3 "Loading in batches..." for i = 1:length(documents):batch_size
        documents_batch = Iterators.take(documents[i:end], batch_size)
        helpers.bulk(
            es_client,
            documents_batch,
            index = index_name,
            stats_only = true
        )
    end
    @info "Loading finished."
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
    end

    return parse_args(s)
end

function main()
    parsed_args = parse_commandline()
    parsed_args["extract-only"] && @info "Extract-only mode enabled."

    # Configuration
    index_name = parsed_args["index_name"]

    # Tika Setup
    Taro.init()

    # ElasticSearch Setup
    es = elasticsearch.Elasticsearch([parsed_args["host"]], port=parsed_args["port"], scheme=parsed_args["scheme"])
    if ! es.ping()
        @error "ElasticSearch is not available at $(parsed_args["host"]):$(parsed_args["port"])"
        exit(1)
    else
        @info "Connected to ElasticSearch at $(parsed_args["host"]):$(parsed_args["port"])"
    end
    parsed_args["extract-only"] || create_index_if_necessary(es, index_name)

    # Extract the documents
    documents = extract_from_directory(parsed_args["directory"])
    
    # Load in batches
    parsed_args["extract-only"] || load_in_batches(es, index_name, documents; batch_size=parsed_args["batch-size"])

    # for document in documents
    #     # Output JSON to files
    #     @info "Saving document $(document["file_name"])..."
    #     open("output/$(document["file_name"]).json", "w") do io
    #         JSON.print(io, document)
    #     end
    # end
end

main()

end # module
