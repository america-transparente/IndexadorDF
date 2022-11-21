module Downloader

using Term.Progress
using JSON
using CSV
using DataFrames
using Downloads
using Dates

import Term: install_term_logger
install_term_logger()

using ArgParse

DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"

function parse_commandline()
    s = ArgParseSettings()

    @add_arg_table s begin
        "link-file"
        help = "CSV with the link, date and CVE of each document"
        required = true
        "output-directory"
        help = "directory where to output the documents"
        required = true
        "--user-agent"
        help = "User agent to be used for the requests"
    end

    return parse_args(s)
end

function download_file(url, output_path; user_agent=DEFAULT_USER_AGENT)
    try
        Downloads.download(url, output_path; timeout=40, headers=Dict(
            "Accept" => "application/pdf",
            "User-Agent" => user_agent
        ))
    catch e
        @error "Error while downloading $(url)." e.message e.response
        return false
    end
    return true
end

function write_metadata(metadata, output_path)
    try
        open(output_path, "w") do io
            println(io, JSON.json(metadata))
        end
    catch e
        @error "Error while writing metadata to file" e
        return false
    end
    return true
end

function main()
    parsed_args = parse_commandline()
    println()

    # Paths
    link_file = parsed_args["link-file"]
    output_directory = parsed_args["output-directory"]

    if !isfile(link_file)
        @error "Link file $(link_file) is not a valid path."
        exit(1)
    end

    if !isdir(output_directory)
        @error "Output directory $(output_directory) is not a valid path."
        exit(1)
    end

    # User agent
    user_agent = get(parsed_args, "user-agent", DEFAULT_USER_AGENT)

    # Warn user if using one thread
    if Threads.nthreads() == 1
        @warn "Using only one thread. Consider using more threads for faster processing."
        @warn "You can set the number of threads by using the --threads option in Julia."
    end

    # Load the links
    @info "Loading links from $(link_file)"
    links = CSV.read(link_file, DataFrame; types=Dict(
        :url => String,
        :cve => String,
        :date => Date,
    ))

    println()

    @info "Processing $(size(links, 1)) links"
    processing_pbar = ProgressBar()
    job = addjob!(processing_pbar; description="Processing links")
    with(processing_pbar) do
        # Check the DataFrame has columns link,cve,date
        if !all(occursin.(["url", "cve", "date"], names(links)))
            @error "Link file $(link_file) does not have the required columns (url,cve,date)."
            exit(1)
        end

        # Check types
        if !all(eltype.([links.url, links.cve, links.date]) .<: [AbstractString, AbstractString, Date])
            @error "Link file $(link_file) does not have the required types (String,String,Date)."
            exit(1)
        end

        # Remove duplicate links
        links = unique(links, :url)

        # Check that all links are HTTPS and not HTTP
        if any(startswith.(links.url, "http://"))
            @info "Link file $(link_file) contains HTTP links. Auto-upgrading to HTTPS."
            links.url = replace.(links.url, "http://" => "https://")
        end

        # Clean CVE column (strip, remove minus sign, alphanum)
        links.cve = replace.(links.cve, r"-" => "")
        links.cve = replace.(links.cve, r"[^a-zA-Z0-9]" => "")

        # Check CVE pattern
        cve_pattern = r"([A-Z0-9]{5,14})(?:^|\s|$)"i
        if !all(match.(cve_pattern, links.cve) .≠ nothing)
            @error "Link file $(link_file) does not have the required CVE pattern."
            exit(1)
        end

        # Check that the URLs are valid
        if !all(occursin.(r"^https?://", links.url))
            @error "Link file $(link_file) does not have the required URL pattern."
            exit(1)
        end

        # Skip already downloaded files
        new_links = filter(row -> !isfile(joinpath(output_directory, row.cve * ".pdf")), links)
        if (size(new_links, 1) < size(links, 1))
            @info "Skipping $(size(links, 1) - size(new_links, 1)) already downloaded files."
            links = new_links
        end
    end

    # Download the documents
    @info "Downloading $(nrow(links)) documents."

    # Multi-threaded download
    download_pbar = ProgressBar()
    foreachprogress(eachrow(links), download_pbar; description="Downloading", parallel=true) do link
        # Download the file
        if !download_file(link.url, joinpath(output_directory, link.cve * ".pdf"); user_agent=user_agent)
            @warn "Skipping $(link.url) because it could not be downloaded."
            return
        end

        # Write the metadata
        metadata = Dict("url" => link.url, "cve" => link.cve, "date" => link.date)
        if !write_metadata(metadata, joinpath(output_directory, link.cve * ".json"))
            @warn "Skipping $(link.url) because its metadata could not be written."
            return
        end
    end
    @info "Done."
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end

end # module
