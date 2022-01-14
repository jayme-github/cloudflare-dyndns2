/**
 * cloudflare-dyndns2
 */

const CF_API_BASEURL = 'https://api.cloudflare.com/client/v4/'

const IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/m;
const IPV6_REGEX = /^(?:(?:[a-fA-F\d]{1,4}:){7}(?:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,2}|:)|(?:[a-fA-F\d]{1,4}:){4}(?:(?::[a-fA-F\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,3}|:)|(?:[a-fA-F\d]{1,4}:){3}(?:(?::[a-fA-F\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,4}|:)|(?:[a-fA-F\d]{1,4}:){2}(?:(?::[a-fA-F\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,5}|:)|(?:[a-fA-F\d]{1,4}:){1}(?:(?::[a-fA-F\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,7}|:)))(?:%[0-9a-zA-Z]{1,})?$/m;
const FQDN_REGEX = /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\.)+[a-zA-Z]{2,63}$)/m;

/**
 * Receives a HTTP request and replies with a response.
 * @param {Request} request
 * @returns {Promise<Response>}
 */
async function handleRequest(request) {
  const url = new URL(request.url)
  const jsonResponse = url.searchParams.get('json')

  // Only GET requests are supported
  if (request.method !== 'GET') {
    return new Response('badrequest', {
      status: 200,
      headers: {
        'Content-Type': 'text/plain;charset=UTF-8',
        'Cache-Control': 'no-store',
      }
    })
  }

  if (url.pathname === '/') {
    return Response.redirect('https://github.com/jayme-github/cloudflare-dyndns2', 301)
  }

  // In the case of a "Basic" authentication, the exchange
  // MUST happen over an HTTPS (TLS) connection to be secure.
  if ('https:' !== url.protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
    throw new BadRequestException('Please use a HTTPS connection.')
  }

  // The "Authorization" header is sent when authenticated.
  if (request.headers.has('Authorization')) {
    // Throws exception when authorization fails.
    const { user, pass } = basicAuthentication(request)
    verifyCredentials(user, pass)
  } else {
    // Not authenticated.
    if (jsonResponse) {
      return new Response(JSON.stringify({ success: false, errors: ['Authentication required',], messages: [] }), {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="cloudflare-dyndns2", charset="UTF-8"',
          'Content-Type': 'application/json;charset=UTF-8',
          'Cache-Control': 'no-store',
        }
      })
    } else {
      return new Response('badauth', {
        status: 401,
        headers: {
          // Prompts the user for credentials.
          'WWW-Authenticate': 'Basic realm="cloudflare-dyndns2", charset="UTF-8"',
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store',
        }
      })
    }
  }
  switch (url.pathname) {
    case '/nic/update':
    // This is the legacy API, requires myip and hostname as well.
    case '/v3/update':
      const hostnames = url.searchParams.get('hostname')
      if (hostnames === null) {
        return new Response('notfqdn', {
          status: 200,
          headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Cache-Control': 'no-store',
          }
        })
      }
      const newIPs = parseNewIPs(url, request.headers)
      console.log('New IPv4: ' + newIPs['A'])
      console.log('New IPv6: ' + newIPs['AAAA'])

      // zoneID's will be cached here to speed up updates for multiple records in the same zone
      let knownZones = {}
      // Speaking messages with some additional context, returned when json param is set
      let jsonMessages = []
      // dyndns2 compatible text messages (https://help.dyn.com/remote-access-api/return-codes/)
      let txtMessages = []
      for (const hostname of hostnames.split(',')) {
        if (!FQDN_REGEX.test(hostname)) {
          txtMessages.push('nofqdn')
          continue
        }
        const zoneName = zoneFromFQDN(hostname)
        console.log('Update for host ' + hostname + ' in zone ' + zoneName)

        var zoneID = knownZones[zoneName]
        if (typeof (zoneID) === 'undefined') {
          // Fetch the ID of the from CF API
          console.log("Fetching zone")
          var { success, error, zoneID } = await getZoneID(zoneName)
          if (!success) {
            console.log('Error fetching zoneID: ' + error)
            // Return nohost of zone not found
            txtMessages.push('nohost')
            continue
          }
          knownZones[zoneName] = zoneID
        }
        console.log('ZoneID: ' + zoneID)

        // Fetch existing records from CF API
        var { success, error, records } = await getRecords(zoneID, hostname)
        if (!success) {
          console.log('Error fetching records: ' + error)
          // Return internal error on cfAPI error
          txtMessages.push('911')
          continue
        }


        let good = false
        let nochg = false
        let dnserr = false
        for (const record of records) {
          console.log(record.type + ' record "' + record.name + '" ID: ' + record.id)
          for (const type of ['A', 'AAAA']) {
            const newIP = newIPs[type]
            if (record.type === type && newIP !== null) {
              if (record.content == newIP) {
                nochg = true
                jsonMessages.push(record.type + ' record ' + record.name + ' is up to date since ' + record.modified_on)
              } else {
                var { success, error } = await patchRecord(record, newIP)
                if (success) {
                  good = true
                  jsonMessages.push(record.type + ' record ' + record.name + ' updated with: ' + newIP)
                } else {
                  dnserr = true
                  console.log('Error updating ' + record.type + ' ' + record.name + ': ' + error)
                }

              }
            }
          }
        }
        // https://help.dyn.com/return-codes/
        // Return only one line per host (in order of appearance in hostname parameter) in format:
        // <status> <list of IPs>
        // IPs separated by comma (in order of appearance in myip parameter).
        // If at least one record of a host was updates, return status "good".
        // If we just encounter noops for a host, return status "nochg".
        // If at leat one error was encountered, return status "dnserr".
        if (dnserr) {
          txtMessages.push('dnserr ' + newIPs['ipList'])
        } else if (good) {
          txtMessages.push('good ' + newIPs['ipList'])
        } else if (nochg) {
          txtMessages.push('nochg ' + newIPs['ipList'])
        } else {
          // This should never be reached
          txtMessages.push('911 ' + newIPs['ipList'])
        }
      }

      if (jsonResponse) {
        return new Response(JSON.stringify({ success: good || nochg, errors: [], messages: jsonMessages }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json;charset=UTF-8',
            'Cache-Control': 'no-store',
          }
        })
      } else {
        return new Response(txtMessages.join('\n'), {
          status: 200,
          headers: {
            'Content-Type': 'text/plain;charset=UTF-8',
            'Cache-Control': 'no-store',
          }
        })
      }

    default:
      return new Response(JSON.stringify({ success: false, errors: ['No route for that URI',], messages: [] }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Cache-Control': 'no-store',
        }
      })
  }
}
/**
 * Patch a record with a new IP
 * @param {Object} record
 * @param {string} newIP
 * @returns {{success: boolean, error: string}}
 */
async function patchRecord(record, newIP) {
  console.log('Updating ' + record.type + ' record ' + record.name + ' with: ' + newIP)
  const init = {
    method: 'PATCH',
    body: JSON.stringify({
      content: newIP,
    }),
  }
  const result = await cfAPI('zones/' + record.zone_id + '/dns_records/' + record.id, CF_DNS_API_TOKEN, init)
  if (!result.success) {
    return {
      success: result.success,
      error: JSON.stringify(result.errors),
    }
  }
  return {
    success: result.success,
    error: '',
  }
}
/**
 * Get all records with a given name
 * @param {string} zoneID
 * @param {string} recordName
 * @returns {{success: boolean, error: string, records: Array}}
 */
async function getRecords(zoneID, recordName) {
  const results = await cfAPI('zones/' + zoneID + '/dns_records?name=' + recordName, CF_DNS_API_TOKEN)
  if (!results.success) {
    return {
      success: results.success,
      error: JSON.stringify(results.errors),
      records: null,
    }
  }
  return {
    success: results.success,
    error: '',
    records: results.result,
  }
}
/**
 * Get the ID of a given zone
 * @param {string} zoneName
 * @returns {{success: boolean, error: string, zoneID: string}}
 */
async function getZoneID(zoneName) {
  const results = await cfAPI('zones?name=' + zoneName, CF_ZONE_API_TOKEN)
  if (!results.success) {
    return {
      success: results.success,
      error: JSON.stringify(results.errors),
      zoneID: '',
    }
  }
  if ((results.result).length == 0) {
    return {
      success: false,
      error: 'Zone not found.',
      zoneID: '',
    }
  }
  // Just return the ID of the first zone found
  return {
    success: results.success,
    error: '',
    zoneID: results.result[0].id,
  }
}
/**
 * Call the Cloudflare API
 * @param {string} url
 * @param {string} apiKey
 * @param {Object} init
 * @returns Object
 */
async function cfAPI(url, apiKey, init = {}) {
  const _url = CF_API_BASEURL + url
  init["headers"] = {
    'content-type': 'application/json;charset=UTF-8',
    'authorization': 'Bearer ' + apiKey,
  }
  try {
    const response = await fetch(_url, init)
    const result = await response.json()
    return result
  } catch (exception) {
    return {
      result: null,
      success: false,
      errors: [exception.toString(),],
      messages: [],
    }
  }
}
/**
 * Get the zone from a hostname (foo.bar of some.foo.bar)
 * @param {string} hostname
 * @returns {string}
 * @throws {InternalServerErrorException}
 */
function zoneFromFQDN(hostname) {
  return hostname.substring(hostname.lastIndexOf('.', hostname.lastIndexOf('.') - 1) + 1, hostname.length)
}
/**
 * Parse the desired new IPv4 and/or IPv6 IP.
 * ipList is returned to keep track of the order of usable IPs for the dyndns2 response
 * @param {URL} url
 * @param {Headers} headers
 * @returns {{ A: string, AAAA: string, ipList: string }}
 * @throws {InternalServerErrorException}
 */
function parseNewIPs(url, headers) {
  let ipList = []
  let newIPv4 = null
  let newIPv6 = null
  const myip = url.searchParams.get('myip')
  if (myip !== null) {
    // myip might contain multiple IPv4/IPv6 IPs, separated by comma.
    // The specs are not clear about what happens when multiple IPs of the same type
    // are provided. We just use first of each type.
    // FIXME: Should support multiple A/AAAA records
    myip.split(',').forEach(function (ip) {
      if (ip.length == 0) { return };
      if (newIPv4 === null && IPV4_REGEX.test(ip)) {
        newIPv4 = ip
        ipList.push(ip)
      } else if (newIPv6 === null && IPV6_REGEX.test(ip)) {
        newIPv6 = ip
        ipList.push(ip)
      }
    })
  }
  if (newIPv6 === null && newIPv4 === null) {
    // The myip parameter did not provide a usable IP.
    // Try to determine a IP from the Cloudflare header (which might be v4 or v6).
    console.log('Got no valid IP from myip, trying header')
    const cfConnectingIP = headers.get('CF-Connecting-IP')
    if (IPV4_REGEX.test(cfConnectingIP)) {
      newIPv4 = cfConnectingIP
      ipList.push(cfConnectingIP)
    } else if (IPV6_REGEX.test(cfConnectingIP)) {
      newIPv6 = cfConnectingIP
      ipList.push(cfConnectingIP)
    }
  }
  if (newIPv6 === null && newIPv4 === null) {
    throw new InternalServerErrorException('Unable to get IP from parameter "myip" or CF-Connecting-IP header.')
  }
  return {
    A: newIPv4,
    AAAA: newIPv6,
    ipList: ipList.join(','),
  }
}
/**
 * Throws exception on verification failure.
 * @param {string} user
 * @param {string} pass
 * @throws {UnauthorizedException}
 */
function verifyCredentials(user, pass) {
  if (BASIC_USER !== user || BASIC_PASS !== pass) {
    throw new UnauthorizedException('Invalid username/password.')
  }
}
/**
 * Parse HTTP Basic Authorization value.
 * @param {Request} request
 * @throws {BadRequestException}
 * @returns {{ user: string, pass: string }}
 */
function basicAuthentication(request) {
  const Authorization = request.headers.get('Authorization')

  const [scheme, encoded] = Authorization.split(' ')

  // The Authorization header must start with "Basic", followed by a space.
  if (!encoded || scheme !== 'Basic') {
    throw new BadRequestException('Malformed authorization header.')
  }

  // Decodes the base64 value and performs unicode normalization.
  // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
  // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
  const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0))
  const decoded = new TextDecoder().decode(buffer).normalize()

  // The username & password are split by the first colon.
  //=> example: "username:password"
  const index = decoded.indexOf(':')

  // The user & password are split by the first colon and MUST NOT contain control characters.
  // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new BadRequestException('Invalid authorization value.')
  }

  return {
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
  }
}

function UnauthorizedException(reason) {
  this.status = 401
  this.statusText = 'Unauthorized'
  this.reason = { success: false, errors: reason, messages: [] }
}

function BadRequestException(reason) {
  this.status = 400
  this.statusText = 'Bad Request'
  this.reason = { success: false, errors: reason, messages: [] }
}

function InternalServerErrorException(reason) {
  this.status = 500
  this.statusText = 'Internal Server Error'
  this.reason = { success: false, errors: reason, messages: [] }
}

addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request).catch(err => {
      const json = JSON.stringify(err.reason || { success: false, errors: ['Unknown Error'], messages: [] })

      return new Response(json, {
        status: err.status || 500,
        statusText: err.statusText || null,
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          // Disables caching by default.
          'Cache-Control': 'no-store',
          // Returns the "Content-Length" header for HTTP HEAD requests.
          'Content-Length': json.length,
        }
      })
    })
  )
})