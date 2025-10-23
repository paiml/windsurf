# Lab 2.2: Secure File Handling and Upload Security

## Overview

This lab covers file upload vulnerabilities, including unrestricted file uploads, path traversal attacks, and MIME type spoofing. You'll learn to use AI tools to identify these issues without exposing your production code.

## Learning Objectives

By the end of this lab, you will:
- Understand common file upload vulnerabilities
- Detect path traversal attacks
- Implement secure file validation
- Prevent MIME type spoofing
- Use AI to analyze file handling patterns securely

## Prerequisites

- Completed Labs 2.1 and Module 1
- Understanding of file systems and web uploads
- Basic knowledge of web frameworks (Express, Flask, etc.)
- Access to an AI tool with secure prompting skills

## Part 1: Understanding File Upload Vulnerabilities

### Common Vulnerability Categories

1. **Unrestricted File Type Uploads**
   - Accepting executable files disguised as images
   - Code execution on server
   - Malware distribution

2. **Path Traversal**
   - `../../../etc/passwd`
   - `..\\..\\windows\\system32\\config\\sam`
   - Overwriting critical system files

3. **MIME Type Spoofing**
   - Manipulating Content-Type headers
   - Malicious executables appearing as images
   - Bypassing client-side validation

4. **File Size Bombs**
   - Zip bombs (small compressed, huge uncompressed)
   - Denial of service via disk exhaustion

5. **Metadata Exploitation**
   - Embedded malicious code in image EXIF data
   - Information disclosure via metadata

## Part 2: Secure Prompting for File Upload Security

### Exercise 1: Pattern-Based AI Query

**❌ Bad Prompt:**
```
Review my file upload code:
[Paste entire production upload handler with S3 keys, bucket names, etc.]
```

**✅ Good Prompt:**
```
What security vulnerabilities exist in this file upload logic pattern?

Process:
1. User selects file through web form
2. File uploaded to server directory: /uploads/user-files/
3. Filename taken directly from user input
4. File extension checked against allowed list: [jpg, png, pdf]
5. File saved with original filename

What vulnerabilities are present and how should they be fixed?
```

### Exercise 2: Query Your AI Tool

Use this prompt:

```
Analyze this generic file upload workflow for security issues:

Workflow:
1. Client submits file via multipart form data
2. Server receives file with original filename
3. Server checks file extension matches allowed types
4. Server saves file to upload directory with original name
5. Server returns URL to uploaded file

Questions:
1. What are the security vulnerabilities?
2. What attacks are possible?
3. How should this be secured?
4. What validation should be performed?
```

**Document AI Response:**
- Vulnerabilities identified: ___________
- Attack scenarios: ___________
- Recommendations: ___________

## Part 3: Hands-On Vulnerable Implementation

### Exercise 3: Analyze Vulnerable Code

```javascript
// VULNERABLE FILE UPLOAD - DO NOT USE IN PRODUCTION
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// VULNERABILITY: No restrictions on storage location
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // VULNERABILITY: Fixed upload directory
        cb(null, '/var/www/uploads/');
    },
    filename: function (req, file, cb) {
        // VULNERABILITY: Using original filename directly
        cb(null, file.originalname);
    }
});

// VULNERABILITY: No file size limits
const upload = multer({ storage: storage });

app.post('/upload', upload.single('file'), (req, res) => {
    // VULNERABILITY: No validation of file type
    // VULNERABILITY: No sanitization of filename
    // VULNERABILITY: No virus scanning

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    // VULNERABILITY: Returns full file path
    res.json({
        message: 'File uploaded successfully',
        filename: req.file.filename,
        path: req.file.path,
        size: req.file.size
    });
});

// VULNERABILITY: Serves uploaded files directly
app.get('/files/:filename', (req, res) => {
    const { filename } = req.params;

    // VULNERABILITY: No validation - path traversal possible!
    const filepath = path.join('/var/www/uploads/', filename);

    res.sendFile(filepath);
});

app.listen(3000);
```

**Your Task:**
Identify all security issues in this code. List:
1. Each vulnerability
2. How it could be exploited
3. Potential impact

## Part 4: Implementing Secure File Uploads

### Exercise 4: Build a Secure File Upload Handler

#### Secure Node.js Implementation

```javascript
// SECURE FILE UPLOAD IMPLEMENTATION
const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs').promises;
const { body, validationResult } = require('express-validator');
const fileType = require('file-type');
const sanitize = require('sanitize-filename');

const app = express();

// Configuration
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/var/data/uploads';
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];

// Ensure upload directory exists and is secure
async function ensureUploadDir() {
    try {
        await fs.access(UPLOAD_DIR);
    } catch {
        await fs.mkdir(UPLOAD_DIR, { recursive: true, mode: 0o750 });
    }
}

ensureUploadDir();

// Secure filename generation
function generateSecureFilename(originalName) {
    // Extract extension
    const ext = path.extname(originalName).toLowerCase();

    // Validate extension
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        throw new Error('Invalid file extension');
    }

    // Generate random filename
    const randomName = crypto.randomBytes(16).toString('hex');
    return `${randomName}${ext}`;
}

// Configure multer with security settings
const storage = multer.diskStorage({
    destination: async function (req, file, cb) {
        // Store in subdirectory by date to avoid large directories
        const date = new Date();
        const subdir = path.join(
            UPLOAD_DIR,
            date.getFullYear().toString(),
            (date.getMonth() + 1).toString().padStart(2, '0')
        );

        try {
            await fs.mkdir(subdir, { recursive: true, mode: 0o750 });
            cb(null, subdir);
        } catch (error) {
            cb(error, null);
        }
    },
    filename: function (req, file, cb) {
        try {
            const secureFilename = generateSecureFilename(file.originalname);
            cb(null, secureFilename);
        } catch (error) {
            cb(error, null);
        }
    }
});

// File filter for initial validation
function fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();

    if (!ALLOWED_EXTENSIONS.includes(ext)) {
        return cb(new Error('Invalid file type'), false);
    }

    // Check MIME type from multipart header
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        return cb(new Error('Invalid MIME type'), false);
    }

    cb(null, true);
}

const upload = multer({
    storage: storage,
    limits: {
        fileSize: MAX_FILE_SIZE,
        files: 1
    },
    fileFilter: fileFilter
});

// Deep file validation after upload
async function validateFileContent(filepath) {
    // Read file header to verify actual file type
    const type = await fileType.fromFile(filepath);

    if (!type) {
        throw new Error('Could not determine file type');
    }

    if (!ALLOWED_MIME_TYPES.includes(type.mime)) {
        throw new Error('File content does not match allowed types');
    }

    return type;
}

// Secure upload endpoint
app.post('/upload',
    upload.single('file'),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: 'No file uploaded' });
            }

            // Validate file content (not just headers)
            await validateFileContent(req.file.path);

            // Generate safe download URL (not revealing filesystem path)
            const fileId = path.basename(req.file.filename, path.extname(req.file.filename));

            // Store metadata in database (not shown here)
            // - fileId
            // - original sanitized name
            // - upload timestamp
            // - user who uploaded
            // - file size
            // - MIME type

            res.json({
                success: true,
                fileId: fileId,
                message: 'File uploaded successfully'
            });

        } catch (error) {
            // Delete file if validation fails
            if (req.file && req.file.path) {
                await fs.unlink(req.file.path).catch(console.error);
            }

            console.error('Upload error:', error);
            res.status(400).json({
                error: 'File upload failed',
                message: 'Invalid file'
            });
        }
    }
);

// Secure file retrieval endpoint
app.get('/files/:fileId', async (req, res) => {
    try {
        const { fileId } = req.params;

        // Validate fileId format (should be hex string)
        if (!/^[a-f0-9]{32}$/.test(fileId)) {
            return res.status(400).json({ error: 'Invalid file ID' });
        }

        // Look up file in database to get actual path
        // This prevents path traversal
        // const fileRecord = await db.getFile(fileId);

        // For demo, construct path (in production, use database)
        // Search for file with this ID
        const files = await fs.readdir(UPLOAD_DIR, { recursive: true });
        const matchingFile = files.find(f => f.startsWith(fileId));

        if (!matchingFile) {
            return res.status(404).json({ error: 'File not found' });
        }

        const filepath = path.join(UPLOAD_DIR, matchingFile);

        // Prevent path traversal
        const realPath = await fs.realpath(filepath);
        if (!realPath.startsWith(UPLOAD_DIR)) {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Set appropriate headers
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', 'attachment');
        res.setHeader('X-Content-Type-Options', 'nosniff');

        res.sendFile(realPath);

    } catch (error) {
        console.error('File retrieval error:', error);
        res.status(500).json({ error: 'File retrieval failed' });
    }
});

// Error handling
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'File too large',
                maxSize: MAX_FILE_SIZE
            });
        }
    }

    console.error('Error:', error);
    res.status(500).json({ error: 'An error occurred' });
});

app.listen(3000, () => {
    console.log('Secure file upload server running on port 3000');
});
```

#### Secure Python/Flask Implementation

```python
# SECURE FILE UPLOAD - Python/Flask
import os
import hashlib
import magic
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
import uuid

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/var/data/uploads')
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
ALLOWED_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
}

# Ensure upload directory exists
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True, mode=0o750)

def allowed_file(filename):
    """Check if filename has allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_content(filepath):
    """Validate actual file content using magic numbers."""
    mime = magic.from_file(filepath, mime=True)
    return mime in ALLOWED_MIME_TYPES

def generate_secure_filename(original_filename):
    """Generate a secure random filename."""
    ext = Path(original_filename).suffix.lower()
    if ext[1:] not in ALLOWED_EXTENSIONS:
        raise ValueError('Invalid file extension')

    random_name = uuid.uuid4().hex
    return f"{random_name}{ext}"

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if file is present
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Validate file extension
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400

    try:
        # Generate secure filename
        secure_name = generate_secure_filename(file.filename)

        # Create date-based subdirectory
        from datetime import datetime
        now = datetime.now()
        subdir = Path(UPLOAD_FOLDER) / str(now.year) / f"{now.month:02d}"
        subdir.mkdir(parents=True, exist_ok=True, mode=0o750)

        filepath = subdir / secure_name

        # Save file
        file.save(str(filepath))

        # Validate file content (not just extension)
        if not validate_file_content(str(filepath)):
            filepath.unlink()  # Delete invalid file
            return jsonify({'error': 'Invalid file content'}), 400

        # Check file size after saving
        if filepath.stat().st_size > MAX_FILE_SIZE:
            filepath.unlink()
            return jsonify({'error': 'File too large'}), 400

        # Extract file ID from filename
        file_id = Path(secure_name).stem

        # In production, store metadata in database
        # db.store_file_metadata(file_id, original_filename, user_id, etc.)

        return jsonify({
            'success': True,
            'fileId': file_id,
            'message': 'File uploaded successfully'
        }), 201

    except Exception as e:
        app.logger.error(f'Upload error: {e}')
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/files/<file_id>', methods=['GET'])
def get_file(file_id):
    try:
        # Validate file_id format (UUID hex)
        if not all(c in '0123456789abcdef' for c in file_id) or len(file_id) != 32:
            return jsonify({'error': 'Invalid file ID'}), 400

        # In production, look up file path in database
        # file_record = db.get_file(file_id)
        # filepath = file_record.path

        # For demo, search for file
        for root, dirs, files in os.walk(UPLOAD_FOLDER):
            for filename in files:
                if filename.startswith(file_id):
                    filepath = Path(root) / filename

                    # Prevent path traversal
                    if not str(filepath.resolve()).startswith(UPLOAD_FOLDER):
                        return jsonify({'error': 'Access denied'}), 403

                    return send_file(
                        filepath,
                        as_attachment=True,
                        mimetype='application/octet-stream'
                    )

        return jsonify({'error': 'File not found'}), 404

    except Exception as e:
        app.logger.error(f'File retrieval error: {e}')
        return jsonify({'error': 'File retrieval failed'}), 500

if __name__ == '__main__':
    app.run(debug=False)
```

## Part 5: Testing File Upload Security

### Exercise 5: Attack Testing

Test your secure implementation with these attack vectors:

#### Test 1: Path Traversal
```bash
# Try uploading with malicious filename
curl -F "file=@test.jpg;filename=../../../etc/passwd" http://localhost:3000/upload
```

Expected: Filename sanitized, path traversal prevented

#### Test 2: MIME Type Spoofing
```bash
# Create a malicious file
echo '#!/bin/bash\necho "hacked"' > malicious.jpg

# Try to upload
curl -F "file=@malicious.jpg" -H "Content-Type: image/jpeg" http://localhost:3000/upload
```

Expected: Deep content validation rejects file

#### Test 3: File Size Bomb
```bash
# Try uploading large file
dd if=/dev/zero of=large.jpg bs=1M count=10
curl -F "file=@large.jpg" http://localhost:3000/upload
```

Expected: Size limit enforced

#### Test 4: Double Extension
```bash
# Try bypassing with double extension
curl -F "file=@malware.jpg.php" http://localhost:3000/upload
```

Expected: Only last extension validated

### Exercise 6: Use AI for Advanced Scenarios

Prompt your AI tool:

```
What additional file upload security measures should be considered for:
1. Image processing (thumbnails)
2. Document conversion (PDF to text)
3. Virus scanning integration
4. Cloud storage (S3, Azure Blob)
5. CDN integration
```

## Verification Checklist

- [ ] Understand file upload vulnerability types
- [ ] Used secure prompting with AI
- [ ] Generate random filenames (not user-provided)
- [ ] Validate file content (not just extension)
- [ ] Enforce file size limits
- [ ] Prevent path traversal
- [ ] Store files outside web root
- [ ] Implement proper access controls
- [ ] Test with attack payloads

## Security Best Practices

1. **Never trust user input** - Including filenames
2. **Generate random filenames** - Don't use original names
3. **Validate file content** - Check magic numbers, not extensions
4. **Limit file sizes** - Prevent DoS attacks
5. **Store outside web root** - Files shouldn't be directly accessible
6. **Use allowlists** - Never denylists for file types
7. **Scan for malware** - Integrate antivirus scanning
8. **Audit uploads** - Log all upload attempts

## Discussion Questions

1. Why is checking file extensions insufficient?
2. How can images contain malicious code?
3. What's the difference between MIME type in headers vs. file content?
4. Why generate random filenames instead of sanitizing user filenames?
5. How does storing files outside the web root improve security?

## Additional Challenges

1. Implement antivirus scanning with ClamAV
2. Add image processing with security checks
3. Implement file quarantine for suspicious uploads
4. Create an upload rate limiter
5. Add file encryption at rest

## Next Steps

In the next lab, you'll learn about HTTP header security including CSP, CORS, and other security headers that protect against XSS and other attacks.

## Additional Resources

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [File Type Detection with Magic Numbers](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [Secure File Storage Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html)
