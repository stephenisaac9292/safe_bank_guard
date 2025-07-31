from django.contrib import admin
from .models import PhishingReport

@admin.register(PhishingReport)
class PhishingReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'url', 'created_at', 'detected_by', 'ip_address']
    list_filter = ['created_at', 'detected_by']
    search_fields = ['url', 'description', 'ip_address', 'user_agent']
    readonly_fields = ['created_at', 'ip_address', 'user_agent']

    fieldsets = (
        (None, {
            'fields': ('url', 'description', 'screenshot')
        }),
        ('Detection Info', {
            'fields': ('detected_by', 'created_at', 'ip_address', 'user_agent')
        }),
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return True
