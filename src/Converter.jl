module Converter

using Taro
using Pipe: @pipe
using ArgParse
using JSON
using Term.Progress

import Term: install_term_logger
install_term_logger()

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

function extract_document(input_file, tag; scan=false)
    local meta
    local text
    redirect_stdio(stdout=devnull, stderr=devnull) do
        meta, text = Taro.extract(input_file)
    end
    text = clean_text(meta, text)
    getm(key) = get(meta, key, nothing)
    if scan
        # Manually scan for CVE and date
        cve = find_cve(meta, text)
        (ismissing(cve) || cve == "") && @warn "CVE not found in $input_file"
        date = something(getm("Creation-Date"), getm("date"), getm("created"), getm("meta:creation-date"), getm("pdf:docinfo:created"), "")
    else
        # Load the associated JSON file
        json_file = replace(input_file, r"\.pdf$" => ".json")
        # Check that the JSON file exists
        if !isfile(json_file)
            @warn "JSON file $json_file does not exist."
            return
        end
        metadata = JSON.parsefile(json_file)
        cve = metadata["cve"]
        date = metadata["date"]
    end

    document = Dict(
        "title" => something(getm("title"), ""),
        "file_name" => replace(basename(input_file), r"\.pdf$" => ""),
        "tag" => tag,
        "date" => date,
        "cve" => cve,
        "content" => text
    )
    if scan
        document["path"] = relpath(input_file, pwd())
        document["url"] = ""
    else
        document["path"] = ""
        document["url"] = metadata["url"]
    end
    return document
end

function extract_and_load_from_directory(path, output_file, tag; scan=false)
    files = readdir(path, sort = false, join = true)
    n_files = length(files)

    # Filter out non-PDF files
    files = filter(f -> endswith(f, ".pdf"), files)

    # We need to use atomics here because we are using multiple threads
    total_processed, total_failed = (Threads.Atomic{Int}(0), Threads.Atomic{Int}(0))
    n_threads = Threads.nthreads()
    @info "Loading $(n_files) documents with $(n_threads) threads..."
    if n_threads == 1
        @warn "Only one thread available, performance will be significantly impacted. It is recommended to start Julia with threading support through the --threads option."
    end

    write_lock = ReentrantLock()
    pbar = ProgressBar()
    open(output_file, "a") do output
        foreachprogress(files, pbar; parallel=true) do file
            document = extract_document(file, tag; scan=scan)
            if isnothing(document) || document["content"] == ""
                @warn "Skipping $(file) because it seems empty."
                Threads.atomic_add!(total_failed, 1)
                return
            end
            lock(write_lock)
            try
                println(output, JSON.json(document))
            catch e
                @error "Error while writing to file" e
                Threads.atomic_add!(total_failed, 1)
                return
            finally
                unlock(write_lock)
            end
            Threads.atomic_add!(total_processed, 1)
        end
    end
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
        "--scan"
        help = "Manually scan the documents to extract CVE and date"
        action = :store_true
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

    scan = parsed_args["scan"]
    if scan
        @info "Using manual scan mode. No JSON files will be loaded."
    else
        @info "Loading metadata from JSON files. If you want to use manual scan mode, use the --scan option."
    end

    # Tika Setup
    Taro.init()

    # Extract the documents
    extract_and_load_from_directory(input_directory, output_file, tag; scan=scan)
end
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end

end # module
