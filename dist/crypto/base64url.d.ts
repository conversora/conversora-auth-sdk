/**
 * Base64URL encoding & decoding helpers for RFC 9449 and RFC 7638
 */
export declare function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string;
export declare function stringToBase64Url(str: string): string;
export declare function base64UrlDecodeToString(base64url: string): string;
