export const bufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
};

export const base64ToBuffer = (value: string): ArrayBuffer => {
  const binary = atob(value);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

export const utf8ToBuffer = (value: string): ArrayBuffer =>
  new TextEncoder().encode(value).buffer;

export const bufferToUtf8 = (buffer: ArrayBuffer): string =>
  new TextDecoder().decode(buffer);

