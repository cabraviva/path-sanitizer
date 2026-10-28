export interface SanitizeOptions {
  decode?: {
    regex: RegExp
    replacement: string
  }[]
  /**
   * @deprecated Parent-directory filtering is always enforced internally.
   */
  parentDirectoryRegEx?: RegExp
  /**
   * Characters to be removed from paths because the file system doesn't support these.
   */
  notAllowedRegEx?: RegExp
}

interface SanitizeOptionsComplete {
  decode: {
    regex: RegExp
    replacement: string
  }[]
  /**
   * Characters to be removed from paths because the file system doesn't support these.
   */
  notAllowedRegEx: RegExp
}

export const DEFAULT_OPTIONS: SanitizeOptionsComplete = {
  decode: [
    {
      regex: /%2[eE]/g,
      replacement: '.',
    },
    {
      regex: /%2[fF]/g,
      replacement: '/',
    },
    {
      regex: /%5[cC]/g,
      replacement: '\\',
    },
  ],
  notAllowedRegEx: /:|\$|!|'|"|@|\+|`|\||=|\u0000/g,
}

function validateOptions(options: SanitizeOptions): SanitizeOptionsComplete {
  if (!options) return DEFAULT_OPTIONS

  if (typeof options !== 'object') {
    throw new Error('options must be an object')
  }

  return {
    decode: Array.isArray(options.decode)
      ? options.decode
      : DEFAULT_OPTIONS.decode,
    notAllowedRegEx:
      options.notAllowedRegEx ?? DEFAULT_OPTIONS.notAllowedRegEx,
  }
}

function normalizeSlashes(val: string): string {
  // Replace backslashes to forward slashes
  val = val.replaceAll('\\', '/')
  // Replace all multi combined slashes into one
  val = val.replace(/\/+/g, '/')
  return val
}

function decodePath(
  pathstr: string,
  decodeOptions: SanitizeOptionsComplete['decode'],
): string {
  decodeOptions.forEach((decode) => {
    pathstr = pathstr.replace(decode.regex, decode.replacement)
  })

  return pathstr
}

function removeInvalidCharacters(
  pathstr: string,
  notAllowedRegEx: RegExp,
): string {
  return pathstr.replace(notAllowedRegEx, '')
}

function applyPathFilters(pathString: string): string {
  const filteredPath = pathString
    .trim()
    .split('/')
    .filter((segment) => {
      const trimmedSegment = segment.trim()
      return (
        trimmedSegment !== '' &&
        trimmedSegment !== '.' &&
        trimmedSegment !== '..'
      )
    })
    .join('/')
    .trim()
  
  return /^\.+$/.test(filteredPath) ? '' : filteredPath
}

function isSafeLinuxRelativePath(pathString: string): boolean {
  return (
    !pathString.startsWith('/') &&
    !pathString.endsWith('/') &&
    !pathString.split('/').some((segment) => segment === '..')
  )
}

/**
 * Sanitizes a portion of a path to avoid Path Traversal
 */
export default function sanitize(
  pathString: string,
  options: SanitizeOptions = DEFAULT_OPTIONS,
): string {
  // Validate options and set default options if user did not set
  const validOptions = validateOptions(options)

  // Validate path is a string, otherwise convert to string
  if (typeof pathString !== 'string') {
    pathString = `${pathString}`
  }

  if ( pathString.length > 4096 ) {
    throw new Error(`filename is over - 4096 characters`)
  }

  // Apply every configurable transformation before traversal filtering.
  pathString = decodePath(pathString, validOptions.decode)
  pathString = removeInvalidCharacters(
    pathString,
    validOptions.notAllowedRegEx,
  )
  pathString = normalizeSlashes(pathString)
  pathString = applyPathFilters(pathString)

  // No path transformation may happen after this final safety check.
  return isSafeLinuxRelativePath(pathString) ? pathString : ''
}
