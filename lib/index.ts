export interface SanitizeOptions {
  decode?: {
    regex: RegExp
    replacement: string
  }[]
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

/**
 * Internal utility function that validates the SanitizeOptions and fills them with DEFAULT_OPTIONS unless already complete.
 * @param options (incomplete) SanitizeOptions
 * @returns Fully valid SanitizeOptionsComplete
 */
function validateOptions(options: SanitizeOptions): SanitizeOptionsComplete {
  if (!options) return DEFAULT_OPTIONS

  if (typeof options !== 'object') {
    throw new Error('options must be an object')
  }

  return {
    decode: Array.isArray(options.decode)
      ? options.decode
      : DEFAULT_OPTIONS.decode,
    notAllowedRegEx: options.notAllowedRegEx ?? DEFAULT_OPTIONS.notAllowedRegEx,
  }
}

/**
 * Internal utility function to normalize slashes in a path (e.g. from '\' to '/')
 * @param val path string
 * @returns slash-normalized path
 */
function normalizeSlashes(val: string): string {
  // Replace backslashes to forward slashes
  val = val.replaceAll('\\', '/')
  // Replace all multi combined slashes into one
  val = val.replace(/\/+/g, '/')
  return val
}

/**
 * Internal utility function to apply all decode regexes from SanitizeOptions.decode to a path string
 * @param pathstr a path string
 * @param decodeOptions valid SanitizeOptionsComplete.decode
 * @returns a decoded path string
 */
function decodePath(
  pathstr: string,
  decodeOptions: SanitizeOptionsComplete['decode'],
): string {
  for (const decodeOption of decodeOptions) {
    pathstr = pathstr.replace(decodeOption.regex, decodeOption.replacement)
  }

  return pathstr
}

/**
 * Internal utility function to ensure the specified notAllowedRegEx
 */
function removeInvalidCharacters(
  pathstr: string,
  notAllowedRegEx: RegExp,
): string {
  return pathstr.replace(notAllowedRegEx, '')
}

/**
 * Internal function which takes a path string and ensures every segment is valid
 */
function applyPathFilters(pathString: string): string {
  const filteredPath = pathString
    .trim() // trim the whole path-string
    .split('/') // split into path-segments
    .filter((segment) => {
      const trimmedSegment = segment.trim() // trim every segment
      return (
        trimmedSegment !== '' &&
        trimmedSegment !== '.' &&
        trimmedSegment !== '..'
      ) // return whether the segment is a valid path-portion (no '', '.' or '..')
      // if valid => keep; invalid => remove
    })
    .join('/') // reconstruct path string
    .trim() // trim again

  return /^\.+$/.test(filteredPath) ? '' : filteredPath // ensures the path string is not just dots
}

/**
 * Failsafe helper function to catch all remaining absolute paths (not wanted by sanitize())
 * works by ensuring no '/' at start or end and no '..' in a segment in-between
 */
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

  if (pathString.length > 4096) {
    throw new Error(`filename is over - 4096 characters`)
  }

  // Apply every configurable transformation before traversal filtering.
  pathString = decodePath(pathString, validOptions.decode)
  pathString = removeInvalidCharacters(pathString, validOptions.notAllowedRegEx)
  pathString = normalizeSlashes(pathString)
  pathString = applyPathFilters(pathString)

  // No path transformation may happen after this final safety check.
  return isSafeLinuxRelativePath(pathString) ? pathString : ''
}
