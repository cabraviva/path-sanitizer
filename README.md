# path-sanitizer

A simple lightweight npm package for sanitizing paths to prevent Path Traversal

# Usage

```js
import sanitize from 'path-sanitizer'
// or in a common js environment
const sanitize = (await import('path-sanitizer')).default

console.log(sanitize('path/to/file.txt'))
```

Or here is a more complex example:

```js
import sanitize from 'path-sanitizer'
import path from 'path'

// Real scenario:
function routeHandler(myPath) {
  // Lets just assume that the path was extracted from the request
  // We want to read a file in the C:\Users\user\Desktop\myApp\ directory
  // But the user should not be able to access C:\Users\user\Desktop\
  // So we need to sanitize the path

  const APP_DIR = 'C:\\Users\\user\\Desktop\\myApp\\'
  const sanitized = path.join(APP_DIR, sanitize(myPath))

  // Now we would usually read the file
  // But in this case we will just print the path
  console.log(sanitized)
}

routeHandler('my-video.mp4') // Just fine...
routeHandler('../../Documents/grades.docx') // But what if we try to access a file outside the app directory?
routeHandler('/hello.txt') // What if the path starts with a slash, and we try to use an absolute path?
routeHandler('////////a\\\\../hi.txt') // What if the path is not valid?
routeHandler(500) // What if the path is not a string?
routeHandler('/:11^^') // What if the path contains not allowed characters (like ":")?
```
