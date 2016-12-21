from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.utils.translation import ugettext_lazy as _

from forms import LoginForm

def login_user(request):
    form = LoginForm()

    if request.POST:
        form = LoginForm(request.POST)

        username = request.POST.get('username')
        password = request.POST.get('password')


        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return redirect('/')

            else:
                form.errors['username'] = (_(u'This user is deactivated. Please contact your system administrator.'),)
        else:
            form.errors['username'] = (_(u'Wrong username or password!'),)

        return render(request, 'login.html', {'form': form})

    return render(request, 'login.haml', {'form': form})

def logout_user(request):
    logout(request)
    return redirect('/')