# SPDX-License-Identifier: X11
# 2020-10-11
# Simple HTTP server for encrypted writeups

import CSV
import HTTP
import JSON
import Nettle
import Sockets

const ROOTDIR = "/srv/http"
const ASSETS = "$ROOTDIR/ctf-writeups-vault"
const PASSWDFILE = "$ASSETS/passwd"
const PASSWD = CSV.File(PASSWDFILE; delim=':', type=String)

const HOST = Sockets.localhost
const PORT = 5334

const HASH_TYPE = "sha256"

const BAD_REQUEST = 400
const UNAUTHORISED = 401
const NOT_FOUND = 404
const METHOD_NOT_ALLOWED = 405
const FAIL_RESPONSES = Dict(
  BAD_REQUEST        => """
                        {
                          "msg": "Sorry, I only speak JSON.",
                          "ps": "Do you have the right fields?"
                        }
                        """,
  UNAUTHORISED       => "What's the super secret password?\n",
  NOT_FOUND          => "I couldn't find what you're looking for...\n",
  METHOD_NOT_ALLOWED => "POST requests only, please.\n"
)

function httphandler(http::HTTP.Stream)::Nothing
  @show http.message

  # Allow POST only
  if http.message.method != "POST"
    respond_fail(http, METHOD_NOT_ALLOWED)
    return
  end

  # Parse POSTed data
  j = try
    JSON.parse(String(readavailable(http)))
  catch
    respond_fail(http, BAD_REQUEST)
    return
  end

  # Check that received JSON has required keys
  if !(haskey(j, "file") && haskey(j, "flag"))
    respond_fail(http, BAD_REQUEST)
    return
  # Check if requested file exists
  elseif !isfile("$ASSETS/" * j["file"])
    respond_fail(http, NOT_FOUND)
    return
  # Validate flag
  elseif !validate(j["file"], j["flag"])
    respond_fail(http, UNAUTHORISED)
    return
  else
    # Send data!
    HTTP.Streams.setstatus(http, 200)
    HTTP.Streams.setheader(http,
      "Content-Type" => "application/octet-stream")

    HTTP.Streams.startwrite(http)
    write(http, read("$ASSETS/" * j["file"]))
    return
  end
end

function validate(filename::AbstractString, flag::AbstractString)::Bool
  for r ∈ PASSWD
    # Iterate until a matching entry is found
    r.filename != filename && continue

    # Compare the salted hash of the flag
    return Nettle.hexdigest(HASH_TYPE, r.salt * flag) == r.hash
  end
end

function respond_fail(http::HTTP.Stream, status::Int)::Nothing
  # Clear stream to clear my error log~
  readavailable(http)

  HTTP.Streams.setstatus(http, status)
  HTTP.Streams.setheader(http,
    "Content-Type" => "text/plain")

  HTTP.Streams.startwrite(http)
  write(http, FAIL_RESPONSES[status])
  return
end

println("Listening...")
HTTP.Servers.listen(httphandler, HOST, PORT)
