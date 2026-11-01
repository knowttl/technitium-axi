import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { ToolError } from './errors.js';

export class PrivateFiles {
  constructor(private readonly platform = process.platform) {}

  private requireFileProtection(): void {
    if (this.platform === 'win32') throw new ToolError('CONFIG_INSECURE', 'Windows file ownership and ACL verification is PENDING',
      'Use an environment-only profile with an env SecretRef and no config or result file');
  }

  private insecure(path: string): never {
    throw new ToolError('CONFIG_INSECURE', 'Unsafe file ownership, permissions or redirected path',
      `Use an owned regular file and chmod 600 ${path}`);
  }

  private async direct(path: string): Promise<void> {
    if (!isAbsolute(path)) this.insecure(path);
    if ((await lstat(path)).isSymbolicLink() || await realpath(path) !== resolve(path)) this.insecure(path);
  }

  async read(path: string, secret = true): Promise<string> {
    return (await this.readBytes(path, secret)).toString('utf8');
  }

  async readBytes(path: string, secret = true, maxBytes = 16 * 1024 * 1024): Promise<Buffer> {
    const before = await lstat(path);
    this.requireFileProtection();
    await this.direct(path);
    if (!before.isFile() || before.isSymbolicLink()) this.insecure(path);
    if (before.uid !== process.getuid?.() || (before.mode & (secret ? 0o077 : 0o022)) !== 0) this.insecure(path);
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat();
      if (opened.dev !== before.dev || opened.ino !== before.ino) this.insecure(path);
      if (opened.uid !== process.getuid?.() || (opened.mode & (secret ? 0o077 : 0o022)) !== 0) this.insecure(path);
      if (opened.size > maxBytes) throw new ToolError('INPUT_LIMIT', 'Protected file exceeds the input size limit', 'Use a smaller protected file');
      const bytes = await handle.readFile();
      if (bytes.length > maxBytes) throw new ToolError('INPUT_LIMIT', 'Protected file exceeds the input size limit', 'Use a smaller protected file');
      return bytes;
    } finally { await handle.close(); }
  }

  async write(path: string, bytes: string | Uint8Array): Promise<void> {
    this.requireFileProtection();
    if (!isAbsolute(path)) this.insecure(path);
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await this.direct(directory);
    if ((await lstat(directory)).uid !== process.getuid?.()) this.insecure(directory);
    await chmod(directory, 0o700);
    try { await this.read(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const temporary = `${path}.${randomUUID()}.tmp`;
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      await rename(temporary, path);
      const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
      try { await parent.sync(); } finally { await parent.close(); }
    } finally {
      await handle.close();
      await rm(temporary, { force: true });
    }
  }

  async create(path: string, bytes: string): Promise<void> {
    this.requireFileProtection();
    if (!isAbsolute(path)) this.insecure(path);
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await this.direct(directory);
    const parentStat = await lstat(directory);
    if (parentStat.uid !== process.getuid?.() || (parentStat.mode & 0o077) !== 0) this.insecure(directory);
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY);
    try { await parent.sync(); } finally { await parent.close(); }
  }
}
