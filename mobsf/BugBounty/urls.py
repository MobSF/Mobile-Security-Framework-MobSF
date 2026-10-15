"""Workspace routes; JSON APIs require an authenticated Django session and CSRF."""
from django.urls import path

from mobsf.BugBounty import views

urlpatterns = [
    path('', views.programs, name='bounty_workspace'),
    path('programs/<int:pk>/', views.program_detail, name='bounty_program'),
    path('programs/<int:pk>/import/', views.core_import, name='bounty_import'),
    path('analyses/<int:pk>/', views.analysis_detail, name='bounty_analysis'),
    path('analyses/<int:pk>/har/', views.har_import, name='bounty_har'),
    path('analyses/<int:pk>/findings/', views.finding_create,
         name='bounty_finding_create'),
    path('analyses/<int:pk>/export/<str:fmt>/', views.inventory_export,
         name='bounty_export'),
    path('analyses/<int:pk>/compare/<int:other>/', views.compare_versions,
         name='bounty_compare'),
    path('findings/<int:pk>/', views.finding_detail, name='bounty_finding'),
    path('findings/<int:pk>/evidence/', views.evidence_create,
         name='bounty_evidence'),
    path('findings/<int:pk>/report/<str:fmt>/', views.finding_report,
         name='bounty_report'),
    path('api/programs/', views.programs),
    path('api/programs/<int:pk>/', views.program_detail),
    path('api/programs/<int:pk>/import/', views.core_import),
    path('api/analyses/<int:pk>/', views.analysis_detail),
    path('api/analyses/<int:pk>/har/', views.har_import),
    path('api/analyses/<int:pk>/findings/', views.finding_create),
    path('api/findings/<int:pk>/', views.finding_detail),
    path('api/findings/<int:pk>/evidence/', views.evidence_create),
]
