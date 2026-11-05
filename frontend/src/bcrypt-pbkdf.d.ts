declare module 'bcrypt-pbkdf' {
  export function pbkdf(
    password: Uint8Array, passwordLength: number,
    salt: Uint8Array, saltLength: number,
    key: Uint8Array, keyLength: number, rounds: number
  ): number;
}
