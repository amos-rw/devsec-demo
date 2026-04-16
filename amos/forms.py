"""
amos/forms.py

We build on Django's built-in auth forms rather than writing our own from
scratch. This is intentional — those forms already handle password hashing,
timing-safe comparison, and validation in a battle-tested way.

Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#module-django.contrib.auth.forms
"""

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User

from .models import Profile


class RegistrationForm(UserCreationForm):
    """
    Extends UserCreationForm to add an email field.

    UserCreationForm already provides:
      - username validation (uniqueness, allowed characters)
      - password1 / password2 match check
      - the full AUTH_PASSWORD_VALIDATORS pipeline (length, common passwords, etc.)

    We only add email on top; everything else is inherited.

    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.forms.UserCreationForm
    """

    email = forms.EmailField(
        required=True,
        help_text="Required. Enter a valid email address.",
    )

    class Meta:
        model = User
        # Field order determines the render order in templates.
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        """
        Persist the email field, which UserCreationForm does not include
        by default. The Profile is created by the post_save signal, so we
        do not need to create it here.
        """
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    """
    Thin subclass of AuthenticationForm so we can apply custom widget
    attributes (e.g. autofocus, placeholder) while keeping all the
    authentication logic intact.

    AuthenticationForm already:
      - validates credentials with authenticate()
      - blocks inactive accounts
      - does NOT reveal whether the username or the password was wrong
        (prevents user enumeration via error messages)

    Docs: https://docs.djangoproject.com/en/5.2/topics/auth/default/#django.contrib.auth.forms.AuthenticationForm
    """

    username = forms.CharField(
        widget=forms.TextInput(attrs={"autofocus": True, "autocomplete": "username"}),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class ProfileUpdateForm(forms.ModelForm):
    """
    Lets users update their own Profile (bio, avatar, document).

    File fields are validated by the model-level validators declared in
    validators.py (size, extension whitelist, magic-byte check).  Django's
    ModelForm calls full_clean() during is_valid(), which runs those validators
    automatically — no extra work is needed here.

    The view must pass request.FILES as the second positional argument and the
    template form element must carry enctype="multipart/form-data", otherwise
    file data never reaches Django.

    Docs: https://docs.djangoproject.com/en/5.2/topics/forms/modelforms/
    Docs: https://docs.djangoproject.com/en/5.2/topics/http/file-uploads/
    """

    class Meta:
        model = Profile
        fields = ("bio", "avatar", "document")
        widgets = {
            "bio": forms.Textarea(attrs={"rows": 4, "placeholder": "Tell us a little about yourself…"}),
        }
