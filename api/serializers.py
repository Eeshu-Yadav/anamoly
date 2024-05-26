from rest_framework import serializers
from .models import DetectionData

class DetectionDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionData
        fields = '__all__'


