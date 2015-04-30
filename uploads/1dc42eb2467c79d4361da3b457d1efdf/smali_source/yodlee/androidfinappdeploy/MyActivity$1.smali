.class Lyodlee/androidfinappdeploy/MyActivity$1;
.super Ljava/lang/Object;
.source "MyActivity.java"

# interfaces
.implements Landroid/view/MenuItem$OnMenuItemClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lyodlee/androidfinappdeploy/MyActivity;->onCreateOptionsMenu(Landroid/view/Menu;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lyodlee/androidfinappdeploy/MyActivity;


# direct methods
.method constructor <init>(Lyodlee/androidfinappdeploy/MyActivity;)V
    .registers 2

    .prologue
    .line 41
    iput-object p1, p0, Lyodlee/androidfinappdeploy/MyActivity$1;->this$0:Lyodlee/androidfinappdeploy/MyActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onMenuItemClick(Landroid/view/MenuItem;)Z
    .registers 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    .line 45
    iget-object v1, p0, Lyodlee/androidfinappdeploy/MyActivity$1;->this$0:Lyodlee/androidfinappdeploy/MyActivity;

    const v2, 0x7f080001

    invoke-virtual {v1, v2}, Lyodlee/androidfinappdeploy/MyActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/webkit/WebView;

    .line 46
    .local v0, "myWebView":Landroid/webkit/WebView;
    invoke-virtual {v0}, Landroid/webkit/WebView;->reload()V

    .line 47
    const/4 v1, 0x1

    return v1
.end method
