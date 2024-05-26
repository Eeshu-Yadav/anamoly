# anomaly_detection/urls.py
from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api.views import DetectionDataViewSet

router = DefaultRouter()
router.register(r'data', DetectionDataViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
]

