from django.contrib import admin
from .models import DetectionData

@admin.register(DetectionData)
class DetectionDataAdmin(admin.ModelAdmin):
    list_display = (
        'protocol', 'service', 'flag', 'src_bytes', 'dst_bytes', 
        'count', 'same_srv_rate', 'diff_srv_rate', 'dst_host_serve_count', 
        'dst_host_same_serve_count', 'result'
    )
    search_fields = ('protocol', 'service', 'flag', 'result')
    list_filter = ('protocol', 'service', 'flag', 'result')
