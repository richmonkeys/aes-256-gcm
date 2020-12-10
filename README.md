# aes-256-gcm
Node.js aes-256-gcm encryption and decryption implementations with some quality-of-life options.

Installation
-
```bash
npm install node-aes-gcm
```

Usage
-
```typescript
import { encrypt, decrypt } from '@richmonkeys/aes-256-gcm'

const encrypted = encrypt('super secret', 'my-secret-password-key')
```
