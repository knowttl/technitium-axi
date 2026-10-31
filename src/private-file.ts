import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath, rename, rm } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ToolError } from './errors.js';

const execute = promisify(execFile);

async function windowsAcl(path: string, write: boolean): Promise<void> {
  // Paths are data, never interpolated into PowerShell source.
  const script = `$ErrorActionPreference='Stop'; $p=$env:TECHNITIUM_PRIVATE_PATH;
    $item=Get-Item -LiteralPath $p -Force;
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point' };
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User;
    $sids=@($user.Value,'S-1-5-18','S-1-5-32-544');
    $acl=Get-Acl -LiteralPath $p;
    if ($env:TECHNITIUM_PRIVATE_WRITE -eq 'true') {
      $acl.SetAccessRuleProtection($true,$false);
      foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) };
      foreach ($sid in $sids) {
        $identity=[Security.Principal.SecurityIdentifier]::new($sid);
        if ($item.PSIsContainer) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','Allow') };
        $acl.AddAccessRule($rule)
      };
      Set-Acl -LiteralPath $p -AclObject $acl
    } else {
      if (!$acl.AreAccessRulesProtected) { throw 'Inherited ACL' };
      foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $sids) { throw 'Unsafe ACL' }
      }
    }`;
  await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    env: { ...process.env, TECHNITIUM_PRIVATE_PATH: path, TECHNITIUM_PRIVATE_WRITE: String(write) },
  });
}

export class PrivateFiles {
  constructor(private readonly platform = process.platform, private readonly acl = windowsAcl) {}

  private insecure(path: string): never {
    throw new ToolError('CONFIG_INSECURE', 'Unsafe file ownership, permissions or redirected path',
      this.platform === 'win32' ? `Recreate the protected file with technitium-axi: ${path}` : `Use an owned regular file and chmod 600 ${path}`);
  }

  private async direct(path: string): Promise<void> {
    if (!isAbsolute(path) || (this.platform === 'win32' && (!/^[A-Za-z]:[\\/]/.test(path) || path.slice(2).includes(':')))) this.insecure(path);
    if ((await lstat(path)).isSymbolicLink() || await realpath(path) !== resolve(path)) this.insecure(path);
  }

  async read(path: string, secret = true, verifyAcl = false): Promise<string> {
    await this.direct(path);
    const before = await lstat(path);
    if (!before.isFile() || before.isSymbolicLink()) this.insecure(path);
    if (this.platform !== 'win32' && (before.uid !== process.getuid?.() || (before.mode & (secret ? 0o077 : 0o022)) !== 0)) this.insecure(path);
    if (this.platform === 'win32' && verifyAcl) {
      try { await this.acl(path, false); } catch { this.insecure(path); }
    }
    const handle = await open(path, constants.O_RDONLY | (this.platform === 'win32' ? 0 : constants.O_NOFOLLOW));
    try {
      const opened = await handle.stat();
      if (opened.dev !== before.dev || opened.ino !== before.ino) this.insecure(path);
      return await handle.readFile('utf8');
    } finally { await handle.close(); }
  }

  async write(path: string, bytes: string | Uint8Array): Promise<void> {
    if (!isAbsolute(path)) this.insecure(path);
    const directory = dirname(path);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await this.direct(directory);
    if (this.platform === 'win32') await this.acl(directory, true);
    else {
      if ((await lstat(directory)).uid !== process.getuid?.()) this.insecure(directory);
      await chmod(directory, 0o700);
    }
    try { await this.read(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const temporary = `${path}.${randomUUID()}.tmp`;
    const handle = await open(temporary, 'wx', 0o600);
    try {
      if (this.platform === 'win32') await this.acl(temporary, true);
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      const deadline = Date.now() + 1000;
      for (;;) {
        try { await rename(temporary, path); break; }
        catch (error) {
          if (this.platform !== 'win32' || !['EPERM', 'EBUSY', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '') || Date.now() >= deadline) throw error;
          await new Promise(resolve => setTimeout(resolve, 50));
        }
      }
    } finally {
      await handle.close();
      await rm(temporary, { force: true });
    }
  }
}
