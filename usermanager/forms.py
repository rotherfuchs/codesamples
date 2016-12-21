from django.forms import ModelForm
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django.utils.safestring import mark_safe
from django.forms.widgets import TextInput, EmailInput, PasswordInput, DateInput, FileInput

class LoginForm(ModelForm):
    class Meta:
        model = User
        fields = ('username', 'password')
        widgets = {
            'username': TextInput(
                attrs={'class': 'form-control', 'placeholder': _(u'Username')}
            ),
            'password': PasswordInput(
                attrs={'class': 'form-control', 'placeholder': _(u'Password')},
            ),
        }

    def validate_unique(self):
        """ Can be ignored as we are read-only """
        pass