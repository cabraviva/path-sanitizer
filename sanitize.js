const path = require('path')

const DEFAULT_OPTIONS = {
    decode: [
        {
            regex: /%2e/g,
            replacement: '.'
        },
        {
            regex: /%2f/g,
            replacement: '/'
        },
        {
            regex: /%5c/g,
            replacement: '\\'
        }
    ],
    parentDirectoryRegEx: /[\/\\]\.\.[\/\\]/g,
    notAllowedRegEx: /:|\$|!|'|"|@|\+|`|\||=/g
}

function sanitize (pathToSanitize, options = DEFAULT_OPTIONS) {
    if (!options) options = DEFAULT_OPTIONS
    if (typeof options !== 'object') throw new Error('options must be an object')
    if (!options.decode) options.decode = DEFAULT_OPTIONS.decode
    if (!options.parentDirectoryRegEx) options.parentDirectoryRegEx = DEFAULT_OPTIONS.parentDirectoryRegEx
    if (!options.notAllowedRegEx) options.notAllowedRegEx = DEFAULT_OPTIONS.notAllowedRegEx

    if (typeof pathToSanitize !== 'string') {
        // Stringify the path
        pathToSanitize = `${pathToSanitize}`
    }

    let sanitizedPath = pathToSanitize

    // Decode
    options.decode.forEach(decode => {
        sanitizedPath = sanitizedPath.replace(decode.regex, decode.replacement)
    })

    // Replace first (back)slash with a normal slash
    sanitizedPath = sanitizedPath.replace(/^[\/\\]?/, '/')

    // Replace /../ with /
    sanitizedPath = sanitizedPath.replace(options.parentDirectoryRegEx, '/')

    // Replace double (back)slashes with a single slash
    sanitizedPath = sanitizedPath.replace(/[\/\\]+/g, '/')

    // Normalize path
    sanitizedPath = path.normalize(sanitizedPath)

    // Remove / or \ in the end
    while (sanitizedPath.endsWith('/') || sanitizedPath.endsWith('\\')) {
        sanitizedPath = sanitizedPath.slice(0, -1)
    }

    // Remove / or \ in the beginning
    while (sanitizedPath.startsWith('/') || sanitizedPath.startsWith('\\')) {
        sanitizedPath = sanitizedPath.slice(1)
    }

    // Validate path
    sanitizedPath = path.join('', sanitizedPath)

    // Remove not allowed characters
    sanitizedPath = sanitizedPath.replace(options.notAllowedRegEx, '')

    return sanitizedPath
}

module.exports = sanitize