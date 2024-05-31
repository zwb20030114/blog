from django.urls import path
from home.views import IndexView, DetailView

urlpatterns = [
    #首页的路由设置成工
    path('', IndexView.as_view(), name='index'),
    #详情视图
    path('detail/',DetailView.as_view(), name='detail'),
]