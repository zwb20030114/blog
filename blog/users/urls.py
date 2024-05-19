#用于进行urls子应用的路由视图
from django.urls import path
from users.views import RegisterView
urlpatterns = [
    #path的第一个参数是路由
    #path的第二个参数是视图函数名
    path('register/', RegisterView.as_view(),name='register'),
]