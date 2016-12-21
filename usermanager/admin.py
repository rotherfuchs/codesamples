#!/usr/bin/env python

from django.contrib import admin
from models import UserProfile, AuditTrail


class UserProfileAdmin(admin.ModelAdmin):
    list_display = [i.name for i in UserProfile._meta.fields]
admin.site.register(UserProfile, UserProfileAdmin)


class AuditTrailUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'date', 'user', 'level', 'message')
    list_filter = ('level', 'date', 'user__username')
    readonly_fields = [i.name for i in AuditTrail._meta.fields]
    search_fields = (u'user__username', u'message',)
admin.site.register(AuditTrail, AuditTrailUserAdmin)
