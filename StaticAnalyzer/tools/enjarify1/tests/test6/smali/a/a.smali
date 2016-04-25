# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
.class public La/a;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public static testFallthroughSub(ZB)V
    .locals 05
    const-string v0, "Code"

    const v0, 0
    move v0, v0
    move-object v0, v0
    move v1, v0
    invoke-static {v0}, LL/util;->print(I)V
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    const v3, -7.7e7f
    if-eqz p1, :end1
    	move v3, v0
    :end1

    invoke-static {v3}, LL/util;->print(F)V

:start
	const v0, -0x77e7f
	float-to-int v2, v3
	rem-int v1, v0, v2
	add-int v2, v2, v1
	rsub-int/lit8 v2, v2, 111
	rsub-int/lit8 v0, v2, -111
:end
	.catchall {:start .. :end} :target

	if-eqz p0, :end2
:target
	move v2, v0
	:end2
	invoke-static {v2}, LL/util;->print(I)V

    return-void
.end method


.method public static testFallthrough()V
    .locals 04
    const-string v0, "testFallthrough"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    const v0, 0
    const v1, 1
    move v0, v0
    move v1, v1
    invoke-static {v0, v0}, La/a;->testFallthroughSub(ZB)V
    invoke-static {v0, v1}, La/a;->testFallthroughSub(ZB)V
    invoke-static {v1, v1}, La/a;->testFallthroughSub(ZB)V
    invoke-static {v1, v0}, La/a;->testFallthroughSub(ZB)V
    return-void
.end method


.method public static testVirtualClasses()V
    .locals 04
    const-string v0, "testVirtualClasses"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	#new-instance v0, Lﬃ;
	#invoke-direct {v0}, Lﬃ;-><init>()V

    new-instance v0, Lfinal;
    invoke-direct {v0}, Lfinal;-><init>()V

    const v1, 800
	new-instance v0, Lfinal;
    invoke-direct {v0, v1}, Lfinal;-><init>(I)V

    invoke-virtual {v0}, L-2;->printall()V
    #########################################################

	invoke-virtual {v0}, Ljava/util/Stack;->empty()Z
	move-result v1
	invoke-static {v1}, LL/util;->print(I)V

	invoke-virtual {v0, v0}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;
	invoke-virtual {v0, v0}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;


	invoke-virtual {v0}, Lffi;->size()F
	move-result v1
	invoke-static {v1}, LL/util;->print(F)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V
    return-void
.end method

.method public static eq(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;
    .locals 0
    if-eq p0, p1, :else
        const-string p0, "False"
        return-object p0
    :else
        const-string p1, "True"
        return-object p1
.end method

.method public static testClassConstants()V
    .locals 04
    const-string v0, "testClassConstants"
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    #new-instance v0, Lﬃ;
    #invoke-direct {v0}, Lﬃ;-><init>()V

    ############################################################################
    new-instance v0, Lfinal;
    invoke-direct {v0}, Lfinal;-><init>()V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v1
    const-class v2, Lfinal;

    invoke-static {v1, v2}, La/a;->eq(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v2}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static {v1}, LL/util;->print(Ljava/lang/Object;)V

    ############################################################################
    filled-new-array {v0}, [L-2;
    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v1
    const-class v2, [L-2;

    invoke-static {v1, v2}, La/a;->eq(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v2}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static {v1}, LL/util;->print(Ljava/lang/Object;)V

    ############################################################################
    filled-new-array {v0}, [[Lﬃ;
    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v1
    const-class v2, [[Lﬃ;

    invoke-static {v1, v2}, La/a;->eq(Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v2}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static {v1}, LL/util;->print(Ljava/lang/Object;)V

    return-void
.end method


.method public onCreate(Landroid/os/Bundle;)V
    .locals 12
    move-object/from16 v10, p0
    move-object/from16 v11, p1
    invoke-super {v10, v11}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {}, La/a;->testFallthrough()V
    invoke-static {}, La/a;->testVirtualClasses()V
    invoke-static {}, La/a;->testClassConstants()V

    return-void
.end method
