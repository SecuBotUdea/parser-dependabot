from supabase import Client

from app.models.alert_model import AlertModel


class AlertRepository:
    def __init__(self, supabase: Client):
        self.supabase = supabase

    def upsert_alert(self, alert: AlertModel):
        data = alert.model_dump()
        response = self.supabase.table("alerts").upsert(data).execute()
        return response.data

    def get_alert_by_id(self, alert_id: int):
        response = (
            self.supabase.table("alerts")
            .select("*")
            .eq("id", alert_id)
            .single()
            .execute()
        )
        return response.data
