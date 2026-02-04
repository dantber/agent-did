import * as readline from 'readline';

/**
 * Prompt for a password with hidden input
 */
export async function promptPassword(prompt: string = 'Passphrase: '): Promise<string> {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    // Hide input for password
    const stdin = process.stdin;
    if (stdin.isTTY) {
      (stdin as any).setRawMode(true);
    }

    let password = '';
    process.stdout.write(prompt);

    const onData = (char: Buffer) => {
      const c = char.toString('utf8');

      switch (c) {
        case '\n':
        case '\r':
        case '\u0004': // Ctrl+D
          if (stdin.isTTY) {
            (stdin as any).setRawMode(false);
          }
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          rl.close();
          resolve(password);
          break;

        case '\u0003': // Ctrl+C
          if (stdin.isTTY) {
            (stdin as any).setRawMode(false);
          }
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          rl.close();
          reject(new Error('Cancelled by user'));
          break;

        case '\u007f': // Backspace
        case '\b': // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
            // Move cursor back, write space, move back again
            process.stdout.write('\b \b');
          }
          break;

        default:
          // Only accept printable characters
          if (c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126) {
            password += c;
            process.stdout.write('*');
          }
          break;
      }
    };

    stdin.on('data', onData);
  });
}

/**
 * Prompt for confirmation
 */
export async function promptConfirm(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(`${question} (y/n): `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}
