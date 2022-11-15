module IndexadorDF

using Taro
using ProgressMeter
using Pipe: @pipe
using ArgParse
using JSON

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

function extract_document(input_file, tag)
    local meta
    local text
    redirect_stdio(stdout=devnull, stderr=devnull) do
        meta, text = Taro.extract(input_file)
    end
    text = clean_text(meta, text)
    getm(key) = get(meta, key, nothing)
    cve = find_cve(meta, text)
    (ismissing(cve) || cve == "") && @warn "CVE not found in $input_file" meta
    document = Dict(
        "title" => something(getm("title"), ""),
        "file_name" => basename(input_file),
        "path" => relpath(input_file),
        "tag" => tag,
        "date" => something(getm("Creation-Date"), getm("date"), getm("created"), getm("meta:creation-date"), getm("pdf:docinfo:created"), ""),
        "cve" => find_cve(meta, text),
        "content" => text
    )
    return document
end

function extract_and_load_from_directory(path, output_file, tag)
    files = readdir(path, sort = false, join = true)
    n_files = length(files)
    # We need to use atomics here because we are using multiple threads
    total_processed, total_failed = (Threads.Atomic{Int}(0), Threads.Atomic{Int}(0))
    @info "Loading $(n_files) documents with $(Threads.nthreads()) threads..."

    extraction_progress = Progress(n_files; desc = "Loading documents...", dt = 0.3, showspeed = true)

    write_lock = ReentrantLock()
    open(output_file, "a") do output
        Threads.@threads for file in files
            document = extract_document(file, tag)
            if isnothing(document) || document["content"] == ""
                @warn "Skipping $(file) because it seems empty."
                Threads.atomic_add!(total_failed, 1)
                next!(extraction_progress)
                continue
            end
            lock(write_lock)
            try
                println(output, JSON.json(document))
            catch e
                @error "Error while writing to file" e
                Threads.atomic_add!(total_failed, 1)
                next!(extraction_progress)
                continue
            finally
                unlock(write_lock)
            end
            Threads.atomic_add!(total_processed, 1)
            next!(extraction_progress)
        end
    end
    finish!(extraction_progress)
    @info "Loading finished: $(total_processed[]) documents uploaded, $(total_failed[]) documents failed."
    return total_processed, total_failed

end

function parse_commandline()
    s = ArgParseSettings()

    @add_arg_table s begin
        "input-directory"
        help = "directory to be loaded"
        required = true
        "output-file"
        help = "directory where to generate the JSONL file "
        required = true
        "--tag"
        help = "Tag to be used for the documents"
    end

    return parse_args(s)
end

function main()
    parsed_args = parse_commandline()

    # Paths
    input_directory = parsed_args["input-directory"]
    output_file = parsed_args["output-file"]

    if !isdir(input_directory)
        @error "Input directory $(input_directory) is not a valid path."
        return
    end
    if isfile(dirname(output_file))
        @error "Output file $(dirname(output_file)) is not a valid path."
        return
    end

    # Configuration
    tag = get(parsed_args, "tag", nothing)
    if isnothing(tag)
        @warn "No tag specified. Using directory name as tag."
        tag = relpath(input_directory)
    end

    # Tika Setup
    Taro.init()

    # Extract the documents
    extract_and_load_from_directory(input_directory, output_file, tag)
end
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end

end # module
