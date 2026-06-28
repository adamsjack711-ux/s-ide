description = [[
HTTP-level fingerprint for services nmap's stock signature DB misses:
Node.js / Express, OWASP Juice Shop, and Next.js.

Stock nmap -sV often returns "us-srv?", "tcpwrapped", or just "http" for
modern Node app servers because Express hides X-Powered-By by default and
the response body is a SPA index.html with little server-specific text.

This script probes the target with one HTTP GET / and matches against:
  * Response header X-Powered-By containing "Express"
  * ETag in Express's canonical W/"hex-hex" format
  * Body containing OWASP Juice Shop markers
  * Express 404 page ("Cannot GET /path")
  * __NEXT_DATA__ inline script (Next.js)
  * X-Recruiting: /#/jobs (Juice Shop's recruiter easter egg)

On match it updates the port's service/product/extrainfo so service+version
(-sV) output identifies the app, and emits structured script output that
shows in the report.

@usage nmap -sV --script mhp-http-fingerprint <target>
@output
PORT     STATE SERVICE VERSION
8083/tcp open  http    Node.js (OWASP Juice Shop)
| mhp-http-fingerprint:
|   X-Recruiting: /#/jobs
|   Body contains OWASP Juice Shop markers
|_  Product: OWASP Juice Shop
]]

author = "HackingPal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version", "safe"}

local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

-- Run on any HTTP-likely port. `shortport.http` only covers a handful of
-- well-known ports (80, 443, 631, 7080, 8080, 8088, 8888), missing the
-- whole 3000/4xxx/5xxx/8xxx range common to Node app servers (which is
-- exactly the gap we're plugging). Define a broader rule that catches:
--   * the conventional HTTP/HTTPS ports
--   * Node/Express dev ports (3000, 3001, 5000, 9000, ...)
--   * Angular CLI default (4200)
--   * the common alt-HTTP ports (8000-8090, 8443, 8888)
--   * any port nmap already labelled "http" / "https" / "http-alt"
portrule = shortport.port_or_service(
  {80, 81, 443, 3000, 3001, 3030, 4000, 4200, 4321, 5000, 5001, 5050,
   7000, 7001, 8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083, 8088,
   8443, 8888, 9000, 9001, 9090, 9200},
  {"http", "https", "http-alt", "http-proxy", "https-alt", "us-srv"},
  "tcp", "open")

local function lower_get(headers, name)
  if not headers then return nil end
  for k, v in pairs(headers) do
    if string.lower(k) == name then return v end
  end
  return nil
end

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.status then return nil end

  local headers = response.header or {}
  local body = response.body or ""
  local matches = {}
  local product = nil
  local extra = nil

  -- 1. X-Powered-By: Express (direct, highest confidence)
  local xpb = lower_get(headers, "x-powered-by") or ""
  if string.find(string.lower(xpb), "express", 1, true) then
    table.insert(matches, "X-Powered-By: " .. xpb)
    product = "Express"
  end

  -- 2. ETag in Express's default W/"hex-hex" format (etag library defaults).
  local etag = lower_get(headers, "etag") or ""
  if string.match(etag, '^W/"[a-f0-9]+%-[a-f0-9]+"$') then
    table.insert(matches, "ETag in Express default format: " .. etag)
    if not product then product = "Express (likely)" end
  end

  -- 3. Juice Shop body signature (title + meta description).
  if string.find(body, "OWASP Juice Shop", 1, true) then
    table.insert(matches, "Body contains 'OWASP Juice Shop' marker")
    product = "OWASP Juice Shop"
    extra = "Node.js + Express + Angular"
  end

  -- 4. X-Recruiting: /#/jobs is Juice Shop's recruiter easter egg.
  local xrec = lower_get(headers, "x-recruiting") or ""
  if string.find(xrec, "/#/jobs", 1, true) then
    table.insert(matches, "X-Recruiting: " .. xrec)
    if not product then product = "OWASP Juice Shop" end
  end

  -- 5. __NEXT_DATA__ inline script — Next.js SSR/SSG pages embed app state.
  if string.find(body, "__NEXT_DATA__", 1, true) then
    table.insert(matches, "__NEXT_DATA__ inline script")
    if not product then
      product = "Next.js"
      extra = extra or "Node.js + Next.js"
    end
  end

  -- 6. Express "Cannot GET /path" 404 page — try a deliberately-bogus path
  --    so we don't depend on the root response.
  if response.status ~= 404 then
    local probe = http.get(host, port, "/_mhp_express_probe")
    if probe and probe.status == 404 and probe.body
       and string.find(probe.body, "Cannot GET", 1, true) then
      table.insert(matches, "Express 'Cannot GET' 404 page on /_mhp_express_probe")
      if not product then product = "Express" end
    end
  end

  if #matches == 0 then return nil end

  -- Update the port's service/version so -sV output reflects the find.
  if product then
    port.version = port.version or {}
    -- Service name stays "http"; product/extrainfo carry the specifics.
    port.version.name = "http"
    port.version.name_confidence = 10
    port.version.product = product
    if extra then
      port.version.extrainfo = extra
    end
    nmap.set_port_version(host, port, "hardmatched")
  end

  table.insert(matches, "Product: " .. (product or "(unidentified)"))
  return stdnse.format_output(true, matches)
end
