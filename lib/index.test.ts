import { describe, it, expect } from 'vitest'
import sanitize, { DEFAULT_OPTIONS, SanitizeOptions } from './index'
import { join } from 'node:path'

function linuxSlash(str: string) {
  return str.replace(/\\/g, '/')
}

describe('sanitize()', () => {
  it('removes parent directory patterns (e.g., ../)', () => {
    const input = '../../etc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('handles both forward and backslashes for parent directories', () => {
    const input = '..\\..\\etc\\passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('decodes URL-encoded sequences correctly', () => {
    const input = '%2e%2e%2fetc%2fpasswd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('removes disallowed characters', () => {
    const input = '/path/$dir!/file|name.txt'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('path/dir/filename.txt')
  })

  it('normalizes double slashes to a single slash', () => {
    const input = '//path//to//file'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('path/to/file')
  })

  it('trims leading and trailing slashes', () => {
    const input = '/leading/and/trailing/slashes/'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('leading/and/trailing/slashes')
  })

  it('works with path.join for real-world scenarios', () => {
    const basePath = '/var/app-dir/'
    const input = '../../etc/passwd'
    const sanitizedPath = sanitize(input)
    const finalPath = join(basePath, sanitizedPath)
    expect(linuxSlash(finalPath)).toBe('/var/app-dir/etc/passwd')
  })

  it('removes only trailing slashes in final join', () => {
    const basePath = '/var/app-dir'
    const input = '/some/path/'
    const sanitizedPath = sanitize(input)
    const finalPath = join(basePath, sanitizedPath)
    expect(linuxSlash(finalPath)).toBe('/var/app-dir/some/path')
  })

  it('handles empty strings gracefully', () => {
    const input = ''
    const sanitized = sanitize(input)
    expect(sanitized).toBe('')
  })

  it('handles strings that are already safe', () => {
    const input = 'safe/path/file.txt'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('safe/path/file.txt')
  })

  it('allows overriding decode rules via options', () => {
    const input = '%2e%2fpath%2eto%2efile'
    const options: SanitizeOptions = {
      decode: [
        {
          regex: /%2e/g,
          replacement: '',
        },
      ],
    }
    const sanitized = sanitize(input, options)
    expect(sanitized).toBe('%2fpathtofile')
  })

  it('throws if options are not objects', () => {
    // @ts-expect-error: intentional misuse of options type
    expect(() => sanitize('path', 'invalid options')).toThrow(
      'options must be an object',
    )
  })

  it('ensures double (back)slashes are replaced with single slashes', () => {
    const input = '\\\\server\\share\\folder\\\\file'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('server/share/folder/file')
  })

  it('handles deeply nested directory traversal patterns', () => {
    const input = '../../../..//..\\..\\\\path/to/file'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('path/to/file')
  })

  it('ensures options fallback to defaults when missing', () => {
    const input = '../path/to/file'
    const options: SanitizeOptions = {}
    const sanitized = sanitize(input, options)
    expect(sanitized).toBe('path/to/file')
  })

  it('validates paths correctly with special characters', () => {
    const input = 'valid@path#with+special$characters!'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('validpath#withspecialcharacters')
  })

  it('removes trailing slashes with normalize', () => {
    const input = '/path/to/dir/'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('path/to/dir')
  })

  it('removes leading slashes with normalize', () => {
    const input = '/path/to/dir'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('path/to/dir')
  })
})

describe('sanitize() - Vulnerability Tests', () => {
  it('does not allow traversal bypass via encoded sequences like "..=%5c"', () => {
    const input = '..=%5c..=%5c..=%5cetc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).not.toContain('..')
    expect(sanitized).not.toContain('%5c')
    expect(sanitized).toBe('etc/passwd')
  })

  it('does not allow traversal bypass with mixed slashes and encoding', () => {
    const input = '..\\..\\%2fetc\\passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('removes encoded sequences resembling traversal attempts', () => {
    const input = '%2e%2e%5c%2e%2e%5c/etc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('handles deeply encoded traversal patterns', () => {
    const input = '%2e%2e=%5c%2e%2e=%5c../../../../etc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('ensures path.join does not reconstruct invalid paths', () => {
    const basePath = '/var/app-dir'
    const input = '..=%5c..=%5c..=%5c..=%5ctmp/hacked.txt'
    const sanitizedPath = sanitize(input)
    const finalPath = join(basePath, sanitizedPath)
    expect(linuxSlash(finalPath)).toBe('/var/app-dir/tmp/hacked.txt')
  })

  it('validates against payload: "../../../../../../../../tmp/hacked.txt"', () => {
    const basePath = '/var/app-dir'
    const input = '../../../../../../../../tmp/hacked.txt'
    const sanitizedPath = sanitize(input)
    const finalPath = join(basePath, sanitizedPath)
    expect(linuxSlash(finalPath)).toBe('/var/app-dir/tmp/hacked.txt')
  })

  it('blocks traversal attempts with complex obfuscation patterns', () => {
    const input = '%2e%2e\\%2e%2e\\%2e%2e/../etc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('strips multiple encoded slashes or backslashes', () => {
    const input = 'folder/%2f%5csubfolder%2f%5c..%5cfile.txt'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('folder/subfolder/file.txt')
  })

  it('handles payloads containing excessive traversal markers', () => {
    const input = '../../../..\\..\\\\..///etc/passwd'
    const sanitized = sanitize(input)
    expect(sanitized).toBe('etc/passwd')
  })

  it('Protects reported vulnerability #1', () => {
    expect(
      linuxSlash(
        join(
          '/var/app-dir',
          sanitize('..=%5c..=%5c..=%5c..=%5c..=%5c..=%5c..=%5cetc/passwd'),
        ),
      ),
    ).not.toBe('/etc/passwd')
  })

  it('Protects reported vulnerability #2', () => {
    expect(
      linuxSlash(
        join(
          '/var/app',
          sanitize('./../../test/../../../../../../../../../../etc/passwd'),
        ),
      ),
    ).not.toBe('/etc/passwd')
  })

  // Introduced as of GHSA-g5q3-4w22-rmp2
  it('Removes trailing .', () => {
    expect(linuxSlash(sanitize('/var/app/.'))).toBe('var/app')
  })
  it('Removes trailing ..', () => {
    expect(linuxSlash(sanitize('/var/app/..'))).toBe('var/app')
  })
  it('Removes only .', () => {
    expect(linuxSlash(sanitize('.'))).toBe('')
  })
  it('Removes only ..', () => {
    expect(linuxSlash(sanitize('..'))).toBe('')
  })
  it('Removes only dots (...)', () => {
    expect(linuxSlash(sanitize('...'))).toBe('')
  })
  it('Removes ../..', () => {
    expect(linuxSlash(sanitize('../..'))).toBe('')
  })

  // Introduced as of GHSA-rwjg-p967-7224
  describe('Whitespace bypass vulnerabilities (GHSA-56jx-2v5f-3880 & GHSA-rwjg-p967-7224)', () => {
    describe('Leading whitespace defeats traversal guards', () => {
      it('Single leading space bypasses all guards', () => {
        expect(linuxSlash(sanitize(' ../secrets/creds.env'))).toBe(
          'secrets/creds.env',
        )
        expect(linuxSlash(sanitize(' /etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize(' ../../../etc/shadow'))).toBe('etc/shadow')
      })

      it('Multiple leading spaces bypass guards', () => {
        expect(linuxSlash(sanitize('  /etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('   ../../api/users.ts'))).toBe(
          'api/users.ts',
        )
      })

      it('Leading tabs bypass guards', () => {
        expect(linuxSlash(sanitize('\t/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\t../../api/users.ts'))).toBe(
          'api/users.ts',
        )
        expect(linuxSlash(sanitize('\t../..\t'))).toBe('')
      })

      it('Mixed leading whitespace (space + tab)', () => {
        expect(linuxSlash(sanitize(' \t/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\t ../secrets'))).toBe('secrets')
      })

      it('Leading newlines bypass guards', () => {
        expect(linuxSlash(sanitize('\n/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\n../../api/users.ts'))).toBe(
          'api/users.ts',
        )
      })
    })

    describe('Trailing whitespace exposes traversal components', () => {
      it('Trailing whitespace on relative paths', () => {
        expect(linuxSlash(sanitize('../.. '))).toBe('')
        expect(linuxSlash(sanitize('../..\t'))).toBe('')
        expect(linuxSlash(sanitize('../..\n'))).toBe('')
      })

      it('Trailing whitespace on absolute paths', () => {
        expect(linuxSlash(sanitize('/etc/passwd '))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('/etc/passwd\t'))).toBe('etc/passwd')
      })
    })

    describe('Combined leading and trailing whitespace', () => {
      it('Whitespace bookends on traversal paths', () => {
        expect(linuxSlash(sanitize('\t../..\t'))).toBe('')
        expect(linuxSlash(sanitize(' ../../ '))).toBe('')
        expect(linuxSlash(sanitize('\n../../../\n'))).toBe('')
      })

      it('Whitespace bookends on absolute paths', () => {
        expect(linuxSlash(sanitize('\t/etc/passwd\t'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize(' /etc/shadow '))).toBe('etc/shadow')
      })

      it('Whitespace bookends on mixed paths', () => {
        expect(linuxSlash(sanitize(' /../etc/passwd '))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\t./../secrets\t'))).toBe('secrets')
      })
    })

    describe('CVE-2024-56198 specific payloads with whitespace variations', () => {
      it('Tab hides absolute paths (original CVE)', () => {
        expect(linuxSlash(sanitize('\t/etc/passwd'))).toBe('etc/passwd')
      })

      it('Space variant of CVE payload', () => {
        expect(linuxSlash(sanitize(' /etc/passwd'))).toBe('etc/passwd')
      })

      it('Whitespace-wrapped parent directory escape', () => {
        expect(linuxSlash(sanitize('\t../..\t'))).toBe('')
        expect(linuxSlash(sanitize(' ../../ '))).toBe('')
      })

      it('Multi-level traversal with leading whitespace', () => {
        expect(linuxSlash(sanitize('\t../../api/users.ts'))).toBe(
          'api/users.ts',
        )
        expect(linuxSlash(sanitize(' ../../../etc/secret'))).toBe('etc/secret')
      })
    })

    describe('Idempotence check - output should be sanitizable', () => {
      it('Sanitized output can be sanitized again safely', () => {
        const firstPass = sanitize(' ../secrets/creds.env')
        const secondPass = sanitize(firstPass)
        // Should not degrade or change on second pass
        expect(linuxSlash(secondPass)).toBe(linuxSlash(firstPass))
      })

      it('Multiple sanitization passes are consistent', () => {
        const input = '\t../../etc/passwd'
        const first = linuxSlash(sanitize(input))
        const second = linuxSlash(sanitize(sanitize(input)))
        const third = linuxSlash(sanitize(sanitize(sanitize(input))))
        expect(first).toBe(second)
        expect(second).toBe(third)
      })
    })

    describe('Edge cases with various whitespace characters', () => {
      it('Vertical tab and form feed', () => {
        expect(linuxSlash(sanitize('\v/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\f../../api'))).toBe('api')
      })

      it('No-break space (unicode)', () => {
        expect(linuxSlash(sanitize('\u00A0/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\u00A0../../../etc'))).toBe('etc')
      })

      it('Multiple different whitespace types combined', () => {
        expect(linuxSlash(sanitize(' \t\n/etc/passwd'))).toBe('etc/passwd')
        expect(linuxSlash(sanitize('\t \n../../api/users.ts'))).toBe(
          'api/users.ts',
        )
      })
    })

    describe('Complex real-world payloads with whitespace', () => {
      it('Hidden absolute paths used for file reading', () => {
        expect(linuxSlash(sanitize(' /proc/self/environ'))).toBe(
          'proc/self/environ',
        )
        expect(linuxSlash(sanitize('\t/var/log/auth.log'))).toBe(
          'var/log/auth.log',
        )
      })

      it('Hidden relative paths for config file access', () => {
        expect(linuxSlash(sanitize(' ../../config/database.yml'))).toBe(
          'config/database.yml',
        )
        expect(linuxSlash(sanitize('\t../../../.env'))).toBe('.env')
      })

      it('Windows-style paths with whitespace', () => {
        expect(sanitize(' ..\\..\\config.ini')).not.toContain('..')
        expect(sanitize('\t..\\windows\\system32')).not.toContain('..')
      })
    })
  })
})
