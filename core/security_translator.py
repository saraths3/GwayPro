import re
import base64
import hashlib
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


class CryptoEngine:
    """
    Symmetric Envelope Encryption Engine using Fernet (AES-128 in CBC mode + HMAC-SHA256).
    Derives a stable, 32-byte URL-safe base64 key from Django's SECRET_KEY.
    """
    _fernet_instance = None

    @classmethod
    def get_fernet(cls):
        if cls._fernet_instance is None:
            raw_secret = getattr(settings, 'CWAY_ENCRYPTION_KEY', None) or settings.SECRET_KEY
            key_digest = hashlib.sha256(raw_secret.encode('utf-8')).digest()
            urlsafe_key = base64.urlsafe_b64encode(key_digest)
            cls._fernet_instance = Fernet(urlsafe_key)
        return cls._fernet_instance

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if not plaintext:
            return ""
        fernet = cls.get_fernet()
        encrypted_bytes = fernet.encrypt(plaintext.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')

    @classmethod
    def decrypt(cls, ciphertext: str) -> str:
        if not ciphertext:
            return ""
        fernet = cls.get_fernet()
        try:
            decrypted_bytes = fernet.decrypt(ciphertext.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except (InvalidToken, Exception):
            # If not valid ciphertext, return as-is
            return ciphertext


class SecretScanner:
    """
    Regular expression based secret and credential detector.
    Identifies high-risk patterns such as AWS tokens, private keys, database URIs,
    and generic API secrets.
    """
    RULES = [
        ('AWS_ACCESS_KEY', re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
        ('RSA_PRIVATE_KEY', re.compile(r'-----BEGIN (?:[A-Z0-9_\- ]+ )?PRIVATE KEY-----')),
        ('DATABASE_URL', re.compile(r'\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^\s"\'`]+')),
        ('GITHUB_TOKEN', re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b')),
        ('CWAY_LIVE_TOKEN', re.compile(r'\b(cwp_live_[a-zA-Z0-9]{32,})\b')),
        ('GENERIC_SECRET', re.compile(r'(?i)\b(?:api_key|apikey|secret_key|private_key|token|auth_token|password)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{12,})["\']?')),
    ]

    @classmethod
    def scan(cls, text: str) -> dict:
        if not text:
            return {'has_secrets': False, 'findings': [], 'count': 0}

        findings = []
        for name, pattern in cls.RULES:
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    'type': name,
                    'count': len(matches)
                })

        return {
            'has_secrets': len(findings) > 0,
            'findings': findings,
            'count': sum(f['count'] for f in findings)
        }

    @classmethod
    def mask_text(cls, text: str) -> tuple[str, list[int]]:
        """
        Masks secrets in text, replacing them with redaction chips.
        Returns (masked_text, list_of_lines_with_secrets).
        """
        if not text:
            return "", []

        lines = text.splitlines()
        secret_line_numbers = set()
        masked_lines = []

        for idx, line in enumerate(lines, start=1):
            modified_line = line
            line_has_secret = False

            # AWS Access Key
            if re.search(r'\bAKIA[0-9A-Z]{16}\b', modified_line):
                modified_line = re.sub(
                    r'\b(AKIA)([0-9A-Z]{12})([0-9A-Z]{4})\b',
                    r'\1************\3 [REDACTED_AWS_KEY]',
                    modified_line
                )
                line_has_secret = True

            # Database URL
            if re.search(r'\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/', modified_line):
                modified_line = re.sub(
                    r'((?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:)([^@\s]+)(@)',
                    r'\1••••••••••••\3',
                    modified_line
                )
                line_has_secret = True

            # GitHub Token
            if re.search(r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b', modified_line):
                modified_line = re.sub(
                    r'\b((?:ghp|gho|ghu|ghs|ghr)_)[a-zA-Z0-9]{32}([a-zA-Z0-9]{4})\b',
                    r'\1••••••••••••••••••••••••••••••••\2 [REDACTED_GITHUB_TOKEN]',
                    modified_line
                )
                line_has_secret = True

            # CwayPro Token
            if re.search(r'\bcwp_live_[a-zA-Z0-9]{32,}\b', modified_line):
                modified_line = re.sub(
                    r'\b(cwp_live_)[a-zA-Z0-9]{28,}([a-zA-Z0-9]{4})\b',
                    r'\1••••••••••••••••••••••••••••\2 [REDACTED_CWAY_TOKEN]',
                    modified_line
                )
                line_has_secret = True

            # Generic Secret Assignment (password, secret, api_key)
            if re.search(r'(?i)\b(?:api_key|apikey|secret_key|private_key|token|auth_token|password)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]{12,}', modified_line):
                def redact_generic(m):
                    prefix = m.group(1)
                    val = m.group(2)
                    masked = val[:2] + '•' * (len(val) - 4) + val[-2:] if len(val) >= 6 else '••••••••'
                    return f"{prefix}{masked} [REDACTED_SECRET]"
                
                modified_line = re.sub(
                    r'(?i)(\b(?:api_key|apikey|secret_key|private_key|token|auth_token|password)\s*[:=]\s*["\']?)([a-zA-Z0-9_\-\.]{12,})',
                    redact_generic,
                    modified_line
                )
                line_has_secret = True

            if line_has_secret:
                secret_line_numbers.add(idx)

            masked_lines.append(modified_line)

        return "\n".join(masked_lines), sorted(list(secret_line_numbers))


class SecurityTranslationLayer:
    """
    Security-focused translation gateway between Frontend and Backend.
    Handles inbound payload encryption and secret detection, as well as
    outbound secret masking and DTO translation for safe rendering.
    """

    @classmethod
    def translate_inbound(cls, content: str, flags: dict, file_path: str = "") -> dict:
        """
        Processes incoming file content from CLI / Frontend:
        - Detects secrets
        - Checks encryption triggers (--encrypt, -e flag, or .env files with secrets)
        - Encrypts content at rest if required
        """
        scan_result = SecretScanner.scan(content)

        # Check explicit flag or implicit security policy (.env files with secrets)
        explicit_encrypt = bool(
            flags.get('encrypt') or
            flags.get('e') or
            flags.get('--encrypt') or
            flags.get('-e') or
            flags.get('secure')
        )

        is_sensitive_env = file_path.endswith('.env') or '.env.' in file_path
        should_encrypt = explicit_encrypt or (is_sensitive_env and scan_result['has_secrets'])

        final_content = content
        if should_encrypt:
            final_content = CryptoEngine.encrypt(content)

        return {
            'content': final_content,
            'is_encrypted': should_encrypt,
            'security_scan': scan_result,
            'raw_length': len(content),
            'encrypted_length': len(final_content) if should_encrypt else len(content),
        }

    @classmethod
    def translate_outbound_file(cls, code_file, user, reveal_secrets: bool = False) -> dict:
        """
        Translates a database CodeFile entity into a sanitized frontend View DTO.
        - Transparently decrypts for the authenticated owner
        - Masks discovered secrets unless reveal_secrets=True
        - Returns line-by-line model with secret line badges
        """
        raw_content = code_file.content or ""
        
        # 1. Decrypt if encrypted at rest
        if code_file.is_encrypted:
            decrypted_content = CryptoEngine.decrypt(raw_content)
        else:
            decrypted_content = raw_content

        # 2. Mask secrets if requested
        if reveal_secrets:
            display_content = decrypted_content
            _, secret_lines = SecretScanner.mask_text(decrypted_content)
        else:
            display_content, secret_lines = SecretScanner.mask_text(decrypted_content)

        secret_lines_set = set(secret_lines)

        # 3. Structure lines for clean, safe rendering
        code_lines = []
        for idx, line in enumerate(display_content.splitlines(), start=1):
            code_lines.append({
                'number': idx,
                'content': line,
                'is_secret_line': idx in secret_lines_set
            })

        return {
            'code_lines': code_lines,
            'raw_content': decrypted_content,
            'display_content': display_content,
            'has_secrets': code_file.security_scan.get('has_secrets', False) or len(secret_lines) > 0,
            'secrets_count': code_file.security_scan.get('count', len(secret_lines)),
            'secret_lines': secret_lines,
            'is_revealed': reveal_secrets,
            'is_encrypted': code_file.is_encrypted,
            'encryption_algorithm': getattr(code_file, 'encryption_algorithm', 'AES-128-CBC-HMAC'),
        }
