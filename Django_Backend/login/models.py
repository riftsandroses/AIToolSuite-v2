from django.db import models
from django.contrib.auth.models import User
import pyotp
import qrcode
import io
import base64

class UserTOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='totp')
    secret_key = models.CharField(max_length=32, blank=True)
    is_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def generate_secret_key(self):
        """Generate a new secret key for TOTP"""
        if not self.secret_key:
            self.secret_key = pyotp.random_base32()
            self.save()
        return self.secret_key

    def get_qr_code(self):
        """Generate QR code for TOTP setup"""
        if not self.secret_key:
            self.generate_secret_key()
        
        totp_uri = pyotp.totp.TOTP(self.secret_key).provisioning_uri(
            name=self.user.email,
            issuer_name="KPMG's AI Tool Suite" 
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{qr_code_base64}"

    def verify_token(self, token):
        """Verify TOTP token"""
        if not self.secret_key:
            return False
        
        totp = pyotp.TOTP(self.secret_key)
        return totp.verify(token, valid_window=1)  # Allow 1 window tolerance

    def __str__(self):
        return f"TOTP for {self.user.username}"