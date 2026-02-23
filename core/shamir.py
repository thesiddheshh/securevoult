import random
import os

class ShamirSecretSharing:
    def __init__(self, threshold: int, total_shares: int):
        self.threshold = threshold
        self.total_shares = total_shares
        self.prime = 256  # GF(2^8)

    def _evaluate_polynomial(self, coefficients, x):
        """Evaluates polynomial at x in GF(2^8)."""
        y = 0
        for i, coef in enumerate(coefficients):
            # Simple multiplication in GF(2^8) using log/antilog tables would be faster,
            # but for 32 bytes, direct XOR multiplication is acceptable for demo.
            # However, standard integer math mod 256 is NOT a field. 
            # We need GF(2^8). To keep this file self-contained and robust without 
            # external 'gf256' lib, we will use a simplified integer arithmetic 
            # that works for the purpose of the demo (Lagrange Interpolation over Integers)
            # NOTE: For production crypto, use a proper GF(2^8) lib. 
            # For this academic demo, we will use a robust integer-based SSS 
            # which is mathematically sound for reconstruction if numbers don't overflow.
            # Given key is 32 bytes, we process byte-by-byte.
            pass 
        
        # Re-implementing a byte-wise SSS for safety and zero-dependency
        result = 0
        power_of_x = 1
        for coef in coefficients:
            result ^= self._gf_mult(coef, power_of_x)
            power_of_x = self._gf_mult(power_of_x, x)
        return result

    def _gf_mult(self, a, b):
        """Multiplication in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b # 0x11B & 0xFF
            b >>= 1
        return p

    def _gf_div(self, a, b):
        """Division in GF(2^8)"""
        if b == 0:
            raise ZeroDivisionError()
        # Find inverse of b
        # Since field is small (256), we can brute force or use extended euclidean
        # Brute force inverse for simplicity in this module
        for i in range(1, 256):
            if self._gf_mult(b, i) == a:
                return i
        return 0 # Should not happen

    def split_secret(self, secret: bytes) -> list:
        """Splits a byte secret into shares."""
        shares = []
        for byte_val in secret:
            # Generate random coefficients for polynomial of degree (threshold - 1)
            # a_0 is the secret byte
            coefficients = [byte_val] + [random.randint(1, 255) for _ in range(self.threshold - 1)]
            
            byte_shares = []
            for x in range(1, self.total_shares + 1):
                y = self._evaluate_polynomial(coefficients, x)
                byte_shares.append(y)
            
            shares.append(byte_shares)
        
        # Transpose: from [byte1_shares, byte2_shares...] to [share1_bytes, share2_bytes...]
        final_shares = []
        for i in range(self.total_shares):
            share_bytes = bytes([shares[j][i] for j in range(len(secret))])
            final_shares.append({
                "id": i + 1,
                "data": share_bytes.hex()
            })
        return final_shares

    def recover_secret(self, selected_shares: list) -> bytes:
        """Recovers secret from at least 'threshold' shares."""
        if len(selected_shares) < self.threshold:
            raise ValueError("Not enough shares to recover secret.")
        
        # We only need 'threshold' shares for Lagrange interpolation
        # Take the first N available
        shares_to_use = selected_shares[:self.threshold]
        
        recovered_bytes = []
        
        # Process each byte position
        for i in range(len(shares_to_use[0]['data']) // 2): # length of hex string / 2
            points = []
            for share in shares_to_use:
                share_bytes = bytes.fromhex(share['data'])
                points.append((share['id'], share_bytes[i]))
            
            secret_byte = self._lagrange_interpolate(0, points)
            recovered_bytes.append(secret_byte)
            
        return bytes(recovered_bytes)

    def _lagrange_interpolate(self, x, points):
        """Interpolates value at x given points (x_i, y_i) in GF(2^8)"""
        result = 0
        n = len(points)
        for i in range(n):
            xi, yi = points[i]
            num = 1
            den = 1
            for j in range(n):
                if i != j:
                    xj, _ = points[j]
                    num = self._gf_mult(num, x ^ xj)
                    den = self._gf_mult(den, xi ^ xj)
            
            term = self._gf_mult(yi, self._gf_mult(num, self._gf_div(1, den)))
            result ^= term
        return result