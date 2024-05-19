from django.shortcuts import render
from django.views import View


# Create your views here.


#定义注册视图
class RegisterView(View):

    def get(self, request):
        return render(request,'register.html')
