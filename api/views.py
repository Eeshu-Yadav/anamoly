from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from pathlib import Path
import pickle

from .models import DetectionData
from .serializers import DetectionDataSerializer
from sklearn.preprocessing import LabelEncoder

class AnomalyDetector:
    def __init__(self, model_path):
        with open(model_path, 'rb') as model_file:
            self.model = pickle.load(model_file)
        # Initialize label encoders for categorical features
        self.protocol_encoder = LabelEncoder()
        self.service_encoder = LabelEncoder()
        self.flag_encoder = LabelEncoder()
        # Fit the encoders with the original training data categories
        # These categories should match those used during training
        self.protocol_encoder.fit(['tcp', 'udp', 'icmp'])
        self.service_encoder.fit(['http', 'ftp', 'smtp'])
        self.flag_encoder.fit(['SF', 'S0', 'REJ'])

    def preprocess(self, data):
        # Assume data format: [protocol, service, flag, feature1, feature2, ..., featureN]
        protocol, service, flag, *features = data
        protocol = self.protocol_encoder.transform([protocol])[0]
        service = self.service_encoder.transform([service])[0]
        flag = self.flag_encoder.transform([flag])[0]
        return [protocol, service, flag] + features

    def predict(self, data):
        processed_data = self.preprocess(data)
        return self.model.predict([processed_data])[0]

class DetectionDataViewSet(viewsets.ModelViewSet):
    queryset = DetectionData.objects.all()
    serializer_class = DetectionDataSerializer

    @action(detail=True, methods=['post'])
    def predict(self, request, pk=None):
        data_instance = self.get_object()
        model_path = Path('model.pkl')  # Adjust the path if necessary
        detector = AnomalyDetector(model_path)

        data = [
            data_instance.protocol, 
            data_instance.service, 
            data_instance.flag, 
            data_instance.src_bytes, 
            data_instance.dst_bytes, 
            data_instance.count, 
            data_instance.same_srv_rate, 
            data_instance.diff_srv_rate, 
            data_instance.dst_host_serve_count, 
            data_instance.dst_host_same_serve_count
        ]
        result = detector.predict(data)
        data_instance.result = "Anomaly detected" if result == 1 else "No anomaly detected"
        data_instance.save()

        return Response({'result': data_instance.result})
