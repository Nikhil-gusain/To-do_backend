from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.validators import BaseValidator

class ImageValidator(BaseValidator):
    def __init__(self, max_size=500* 1024):
        print('init')
        self.max_size = max_size
        super().__init__(limit_value=max_size)

    def __call__(self, value):
        if not hasattr(value, 'size'):
            raise ValidationError(_("Uploaded file does not have a size attribute."))

        if value.size > self.max_size:
            print("inside validator2")
            max_size_mb = self.max_size / (1024 * 1024)
            print(max_size_mb)
            raise ValidationError(
                _("Image size should be less than %(max_size)s mb.") % {'max_size': max_size_mb}
            )

