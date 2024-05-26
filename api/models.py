from django.db import models

class DetectionData(models.Model):
    protocol = models.CharField(max_length=10)
    service = models.CharField(max_length=10)
    flag = models.CharField(max_length=10)
    src_bytes = models.FloatField()
    dst_bytes = models.FloatField()
    count = models.FloatField()
    same_srv_rate = models.FloatField()
    diff_srv_rate = models.FloatField()
    dst_host_serve_count = models.FloatField()
    dst_host_same_serve_count = models.FloatField()
    result = models.CharField(max_length=20, blank=True)  # Store the result of the prediction
