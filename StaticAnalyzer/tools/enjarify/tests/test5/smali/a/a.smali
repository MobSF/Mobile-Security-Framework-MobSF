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
.implements L_;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0
    const-string v0, "I like to move it move it"
    return-object v0
.end method


.method public testMovesSub(IDCJF)V
    .locals 32767
    const v0, 0
    const v1, 0xDEA45E80
    const-wide v2, 0x7828B7E3722EBB90L

    ############################################################################
	move/16 v18204, v32774
	move/16 v31981, v1
	move/16 v12478, v18204
	move-object/16 v22776, v0
	move/16 v10648, v1
	move/16 v32238, v32768
	move-wide/16 v3359, v32772
	move/16 v23874, v32238
	move/16 v30594, v12478
	move/16 v32428, v18204
	move/16 v26844, v0
	move-wide/16 v31696, v32769
	move-wide/16 v252, v32772
	move-object/16 v11409, v26844
	move-wide/16 v28578, v32769
	move-wide/16 v25340, v31696
	move-wide/16 v28578, v2
	move/16 v24664, v32771
	move/16 v747, v18204
	move-wide/16 v19825, v31696
	move-wide/16 v26127, v252
	move-wide/16 v7434, v2
	move/16 v20596, v12478
	move-object/16 v7319, v32767
	move/16 v11982, v26844
	move-wide/16 v14783, v25340
	move/16 v9194, v20596
	move/16 v20448, v32238
	move-wide/16 v24893, v2
	move/16 v20119, v32768
	move-wide/16 v6300, v7434
	move/16 v26794, v12478
	move-object/16 v3672, v11409
	move/16 v18986, v20448
	move-wide/16 v31523, v32769
	move/16 v21751, v11409
	move/16 v5924, v10648
	move-object/16 v18289, v21751
	move/16 v31561, v20596
	move-wide/16 v23185, v26127
	move/16 v30759, v24664
	move-object/16 v11064, v11409
	move-wide/16 v20420, v31523
	move-wide/16 v6049, v3359
	move/16 v959, v12478
	move/16 v11840, v30594
	move-wide/16 v8822, v6300
	move-object/16 v3150, v21751
	move-wide/16 v25008, v26127
	move/16 v26480, v32428
	move/16 v26798, v31981
	move/16 v4208, v30759
	move-object/16 v25135, v32767
	move-wide/16 v19585, v3359
	move/16 v32158, v32771
	move/16 v14161, v1
	move/16 v15255, v30594
	move/16 v25008, v4208
	move-object/16 v872, v25135
	move/16 v32179, v9194
	move-wide/16 v29347, v6300
	move-object/16 v13015, v7319
	move/16 v23812, v11409
	move/16 v23880, v9194
	move-object/16 v28205, v32767
	move-object/16 v7977, v32767
	move/16 v3679, v32428
	move/16 v32645, v30759
	move-object/16 v25063, v13015
	move/16 v16372, v24664
	move-wide/16 v27422, v19825
	move-wide/16 v7674, v8822
	move/16 v18455, v32645
	move-object/16 v4338, v28205
	move-wide/16 v23962, v14783
	move/16 v5841, v10648
	move-object/16 v5372, v11982
	move/16 v7172, v11982
	move/16 v29433, v32645
	move-wide/16 v28718, v19585
	move-wide/16 v9197, v23185
	move/16 v30056, v25008
	move/16 v22238, v10648
	move/16 v30781, v23874
	move-wide/16 v475, v28578
	move/16 v8918, v18986
	move/16 v18273, v20448
	move-wide/16 v1411, v7674
	move-wide/16 v4290, v475
	move-object/16 v24916, v26844
	move-object/16 v5181, v3672
	move/16 v32708, v24664
	move-object/16 v10737, v25063
	move-object/16 v27625, v24916
	move/16 v16026, v18455
	move/16 v8699, v23812
	move/16 v15229, v30781
	move-wide/16 v5774, v475
	move-wide/16 v26350, v3359
	move/16 v23459, v18986
	move-wide/16 v5290, v23185
	move-wide/16 v26715, v5290
	move-wide/16 v13702, v6300
	move-object/16 v12055, v25135
	move/16 v17971, v1
	move/16 v4839, v20448
	move-object/16 v20103, v7319
	move/16 v13381, v30056
	move/16 v14876, v31561
	move-wide/16 v23436, v29347
	move-wide/16 v5517, v4290
	move/16 v18374, v1
	move-object/16 v24925, v25135
	move-wide/16 v30779, v23962
	move/16 v2913, v9194
	move-object/16 v21848, v20103
	move/16 v9639, v24916
	move/16 v7434, v10648
	move/16 v27907, v14876
	move-wide/16 v22688, v6049
	move-wide/16 v13784, v28578
	move/16 v25470, v31561
	move-wide/16 v4258, v29347
	move/16 v4815, v3679
	move-wide/16 v28720, v31523
	move/16 v24824, v18455
	move/16 v7534, v1
	move/16 v13476, v16372
	move/16 v1186, v24664
	move/16 v29736, v2913
	move/16 v31566, v26798
	move-object/16 v8574, v21751
	move/16 v25118, v7172
	move-wide/16 v23688, v22688
	move-object/16 v1983, v7172
	move-wide/16 v10370, v19825
	move/16 v31202, v26798
	move-object/16 v4851, v20103
	move-wide/16 v15255, v23962
	move/16 v18929, v30759
	move/16 v6241, v18273
	move-wide/16 v31691, v29347
	move/16 v28609, v18986
	move-wide/16 v10564, v26350
	move/16 v26704, v23874
	move-wide/16 v476, v252
	move/16 v26898, v18289
	move-wide/16 v14537, v31691
	move-wide/16 v14891, v5290
	move-wide/16 v28811, v14783
	move/16 v6905, v18455
	move-object/16 v17599, v10737
	move-wide/16 v1109, v1411
	move-wide/16 v10157, v23688
	move/16 v14993, v2913
	move/16 v14467, v3679
	move/16 v10135, v31561
	move-wide/16 v2132, v28578
	move-wide/16 v25814, v5774
	move/16 v11916, v15229
	move/16 v5467, v8918
	move-wide/16 v28960, v26715
	move/16 v3082, v31981
	move/16 v18978, v18273
	move/16 v17971, v12478
	move/16 v3234, v23812
	move-wide/16 v7443, v28960
	move/16 v29952, v30056
	move-wide/16 v21369, v28578
	move-object/16 v18130, v21848
	move-object/16 v5635, v3234
	move/16 v4524, v11064
	move/16 v26502, v13381
	move-wide/16 v15166, v29347
	move/16 v4668, v32768
	move/16 v7118, v9194
	move-object/16 v16651, v26898
	move-wide/16 v7058, v28960
	move/16 v8214, v31202
	move/16 v17943, v20448
	move/16 v13289, v23880
	move-wide/16 v18819, v26127
	move/16 v11197, v18929
	move/16 v6979, v30594
	move-object/16 v29088, v28205
	move-object/16 v11875, v11409
	move-object/16 v30981, v7977
	move/16 v21702, v22238
	move/16 v14040, v3082
	move/16 v30611, v3234
	move/16 v5583, v26798
	move/16 v9027, v13289
	move-object/16 v24503, v29088
	move-wide/16 v23105, v25340
	move/16 v27717, v31202
	move-wide/16 v23213, v31523
	move-wide/16 v10140, v23962
	move-object/16 v27545, v9639
	move-wide/16 v4736, v23213
	move-object/16 v5403, v26844
	move-wide/16 v10157, v23962
	move/16 v32092, v31561
	move-wide/16 v13267, v10157
	move-wide/16 v30905, v13702
	move/16 v5452, v13381
	move-wide/16 v24038, v5290
	move-object/16 v9249, v4524
	move-wide/16 v22738, v27422
	move/16 v19998, v16026
	move-object/16 v32117, v24925
	move-wide/16 v10716, v10564
	move/16 v5629, v18204
	move/16 v14005, v747
	move-object/16 v26879, v5372
	move/16 v21215, v32428
	move/16 v32028, v32428
	move-wide/16 v23279, v24038
	move/16 v21981, v21215
	move-wide/16 v16032, v3359
	move/16 v21306, v11064
	move-wide/16 v31304, v26127
	move-wide/16 v32572, v19825
	move/16 v24407, v28609
	move/16 v3532, v31202
	move-wide/16 v29381, v23279
	move/16 v30525, v5467
	move/16 v15998, v8214
	move-wide/16 v23225, v5774
	move-wide/16 v14219, v7058
	move-wide/16 v2785, v28811
	move-wide/16 v13784, v5774
	move-object/16 v30905, v27545
	move/16 v6298, v29736
	move-wide/16 v11832, v23279
	move-wide/16 v15201, v11832
	move-wide/16 v10737, v8822
	move-object/16 v23992, v32117
	move/16 v31442, v20119
	move-object/16 v31286, v872
	move/16 v15690, v5629
	move-wide/16 v4925, v252
	move/16 v30307, v23880
	move/16 v32020, v26480
	move/16 v20170, v32771
	move-object/16 v25010, v25135
	move/16 v20836, v6905
	move-object/16 v16295, v28205
	move/16 v2247, v8214
	move-object/16 v32728, v31286
	move-object/16 v22773, v4338
	move/16 v29004, v26704
	move-object/16 v27410, v4851
	move/16 v8817, v17971
	move/16 v24916, v18273
	move-wide/16 v29024, v6049
	move-wide/16 v14562, v10716
	move/16 v26741, v5403
	move-wide/16 v15544, v4258
	move/16 v18978, v28609
	move-wide/16 v29284, v13702
	move/16 v20103, v7534
	move-wide/16 v6087, v30779
	move-wide/16 v6179, v23436
	move-object/16 v3940, v4524
	move-object/16 v26161, v28205
	move/16 v2147, v23459
	move-wide/16 v16403, v2
	move-wide/16 v7143, v23225
	move-wide/16 v6010, v2785
	move/16 v24273, v31981
	move/16 v14055, v7118
	move/16 v29526, v30594
	move-object/16 v21106, v11409
	move-wide/16 v15443, v31523
	move/16 v19541, v24916
	move-object/16 v8872, v32728
	move-object/16 v1106, v22773
	move-wide/16 v5390, v21369
	move/16 v18486, v5467
	move-wide/16 v26226, v19825
	move/16 v24432, v13476
	move/16 v27972, v30759
	move-wide/16 v24893, v23962
	move-wide/16 v6124, v15166
	move/16 v24802, v18374
	move/16 v6653, v18929
	move/16 v20894, v26480
	move/16 v9714, v19998
	move/16 v16429, v14161
	move-wide/16 v18387, v3359
	move/16 v29780, v24664
	move/16 v4661, v25118
	move/16 v4086, v32020
	move-wide/16 v3291, v5517
	move-wide/16 v26105, v15443
	move/16 v14328, v8574
	move/16 v23578, v24664
	move/16 v28469, v24273
	move-wide/16 v14827, v5390
	move/16 v12343, v29952
	move/16 v2001, v5841
	move-object/16 v14262, v13015
	move-wide/16 v15617, v10370
	move-wide/16 v17999, v4925
	move-wide/16 v23082, v29347
	move-wide/16 v21454, v29284
	move/16 v21983, v959
	move/16 v14804, v5452
	move-wide/16 v15272, v23185
	move/16 v12918, v7118
	move/16 v20482, v32645
	move-object/16 v32547, v32728
	move-object/16 v3548, v25010
	move/16 v16335, v27907
	move/16 v25731, v24824
	move/16 v31900, v23874
	move-wide/16 v3274, v2132
	move/16 v22392, v16335
	move-wide/16 v29163, v2785
	move/16 v2894, v32768
	move-object/16 v11269, v3548
	move-wide/16 v19164, v5390
	move-object/16 v27366, v13015
	move-wide/16 v15557, v32572
	move-object/16 v30307, v17599
	move-object/16 v23968, v14262
	move-wide/16 v3765, v7143
	move-wide/16 v2674, v14537
	move-object/16 v21573, v31286
	move-wide/16 v4651, v26127
	move-object/16 v6748, v30307
	move-wide/16 v19496, v32769
	move-object/16 v16169, v32767
	move-wide/16 v6114, v14562
	move-object/16 v21563, v16295
	move-wide/16 v728, v16032
	move/16 v24327, v5841
	move/16 v28303, v3672
	move-object/16 v17215, v5181
	move-wide/16 v29209, v23225
	move-wide/16 v11166, v26350
	move-wide/16 v24193, v6300
	move/16 v16352, v3532
	move-object/16 v15170, v21573
	move-wide/16 v2285, v11832
	move/16 v5600, v23880
	move/16 v10800, v20596
	move/16 v5541, v5467
	move-wide/16 v12966, v15617
	move/16 v7629, v2247
	move-wide/16 v22104, v29284
	move-wide/16 v28590, v3359
	move/from16 v117, v26844
	move/16 v3725, v6905
	move/16 v12358, v17943
	move-wide/16 v11376, v25340
	move/16 v5629, v24916
	move/16 v5290, v25008
	move-wide/16 v515, v5517
	move/16 v31598, v4661
	move-object/16 v7976, v25135
	move/16 v10439, v0
	move/16 v8649, v29004
	move/16 v4258, v4524
	move-wide/16 v3932, v29163
	move/16 v1981, v21306
	move-wide/16 v23283, v2785
	move-object/16 v26546, v17215
	move-object/16 v21868, v15170
	move-object/16 v12274, v32117
	move/16 v29003, v32158
	move-object/16 v31463, v4851
	move-wide/16 v19639, v5774
	move-object/16 v352, v8872
	move/16 v31696, v20170
	move/16 v8761, v16651
	move/16 v21580, v10648
	move/16 v16933, v3082
	move-object/16 v17876, v30981
	move/16 v11782, v20103
	move/16 v23283, v20482
	move/16 v21163, v5403
	move/16 v28296, v5629
	move-wide/16 v3274, v23436
	move-object/16 v836, v4338
	move/16 v30446, v30781
	move/from16 v240, v26502
	move-object/16 v5981, v32547
	move/16 v11166, v11197
	move-wide/16 v7914, v10737
	move-wide/16 v1971, v21369
	move/16 v12032, v27907
	move-object/16 v1800, v7976
	move/16 v30772, v20482
	move-wide/16 v28642, v14891
	move/16 v15761, v29003
	move/16 v12826, v3082
	move-wide/16 v30026, v19164
	move-object/16 v29131, v7977
	move-object/16 v9934, v12055
	move/16 v6026, v12478
	move/16 v13702, v8761
	move/16 v26841, v3234
	move/16 v2492, v15229
	move-wide/16 v7177, v26350
	move/16 v29054, v10135
	move-object/16 v8961, v30611
	move/16 v27471, v24273
	move/16 v5981, v23812
	move/16 v16092, v7118
	move-wide/16 v14650, v2785
	move/16 v18675, v19998
	move/16 v18722, v32028
	move/16 v8214, v30759
	move-object/16 v28386, v29131
	move/16 v19639, v5924
	move/16 v15446, v31900
	move-object/16 v7058, v12055
	move/16 v23264, v30772
	move-wide/16 v14065, v11376
	move/16 v24788, v117
	move/16 v7428, v8649
	move/16 v29249, v18273
	move/16 v22307, v18986
	move/16 v19357, v27717
	move/16 v14579, v21702
	move-wide/16 v1095, v16403
	move-object/16 v20985, v352
	move-wide/16 v16055, v5390
	move/16 v23160, v28469
	move/16 v25957, v2001
	move-wide/16 v20033, v7143
	move/16 v4548, v27717
	move/16 v617, v4548
	move/16 v17620, v25008
	move/16 v10865, v20448
	move-wide/16 v1523, v26715
	move/16 v4453, v9714
	move/16 v15391, v24824
	move/16 v10772, v6026
	move-wide/16 v14871, v2285
	move/16 v18378, v4086
	move-wide/16 v1084, v3765
	move/16 v2896, v25470
	move/16 v25808, v10648
	move-wide/16 v2262, v26105
	move/16 v19102, v17215
	move/16 v2497, v31900
	move/16 v13593, v26704
	move-wide/16 v13775, v14562
	move-wide/16 v23839, v728
	move-wide/16 v17396, v6179
	move-object/16 v3175, v9639
	move-object/16 v691, v4258
	move/16 v32363, v15229
	move-object/16 v6489, v9934
	move/16 v12971, v4661
	move/16 v11200, v15446
	move-object/16 v2093, v7319
	move-wide/16 v20067, v11832
	move-wide/16 v16380, v23839
	move-wide/16 v31439, v27422
	move/16 v12482, v12971
	move/16 v342, v19639
	move/16 v13865, v6905
	move-wide/16 v5756, v7177
	move-wide/16 v3430, v26715
	move-object/16 v13281, v7058
	move-wide/16 v32534, v28718
	move-object/16 v9766, v8872
	move/16 v29704, v3679
	move/16 v6690, v31442
	move/16 v2964, v32092
	move-object/16 v30535, v4338
	move-wide/16 v21494, v1084
	move/16 v1673, v5600
	move-wide/16 v30069, v3430
	move-wide/16 v28276, v20033
	move-object/16 v31807, v6748
	move/16 v28049, v5452
	move/16 v8633, v5541
	move/16 v19856, v25118
	move-object/16 v28982, v32547
	move/16 v15581, v24273
	move-wide/16 v5517, v3765
	move/16 v19164, v28296
	move-wide/16 v6326, v23688
	move/16 v29187, v21702
	move-wide/16 v11379, v21494
	move-object/16 v6654, v4851
	move/16 v19750, v20119
	move-wide/16 v32632, v28578
	move/16 v11200, v9194
	move-wide/16 v27584, v11379
	move/16 v1713, v2492
	move/16 v6517, v32028
	move-wide/16 v10534, v20420
	move/16 v25073, v17620
	move-wide/16 v2104, v6010
	move/16 v6862, v20170
	move-wide/16 v382, v1411
	move/16 v2773, v3725
	move-wide/16 v8685, v6326
	move-wide/16 v21605, v14783
	move-wide/16 v20034, v2132
	move-wide/16 v16632, v15544
	move-wide/16 v7058, v13267
	move/16 v14761, v26841
	move/16 v23472, v32092
	move/16 v21573, v2497
	move-object/16 v24422, v11409
	move-wide/16 v7073, v25340
	move/16 v18418, v18986
	move/16 v1029, v31202
	move-wide/16 v14579, v21454
	move/16 v31240, v21702
	move/16 v20860, v12358
	move-wide/16 v17132, v14065
	move/16 v5982, v13593
	move-object/16 v15983, v691
	move/16 v32061, v5541
	move/16 v18642, v23874
	move/16 v11219, v5841
	move/16 v31400, v31981
	move/16 v10700, v30446
	move/16 v22104, v2894
	move/16 v21276, v25470
	move-wide/16 v1415, v28960
	move/16 v32627, v21580
	move-object/16 v9674, v25063
	move/16 v19429, v27545
	move/16 v2479, v19998
	move/16 v4462, v15761
	move-object/16 v27671, v4524
	move/16 v17659, v30056
	move-wide/16 v5760, v20420
	move/16 v26129, v28469
	move-object/16 v18734, v9934
	move-object/16 v30227, v30981
	move-object/16 v13784, v13281
	move-wide/16 v9648, v16055
	move-object/16 v20103, v25118
	move/16 v2900, v9639
	move-wide/16 v16942, v31523
	move/16 v22208, v19639
	move/16 v14510, v30525
	move/16 v10737, v2913
	move-object/16 v13717, v7319
	move-wide/16 v20531, v1109
	move-object/16 v26841, v30535
	move-wide/16 v18331, v5760
	move-wide/16 v20644, v15255
	move-wide/16 v25057, v20420
	move/16 v617, v12358
	move/16 v24926, v27907
	move-wide/16 v18273, v8822
	move-object/16 v464, v12971
	move-wide/16 v7440, v16055
	move-wide/16 v18170, v6124
	move/16 v3651, v29249
	move-object/16 v24787, v5635
	move-object/16 v18172, v13281
	move/16 v7819, v28049
	move-object/16 v16477, v14262
	move/16 v17359, v25008
	move-wide/16 v23584, v21369
	move-wide/16 v1106, v1095
	move/16 v17217, v32627
	move/16 v1298, v20170
	move/16 v5528, v19998
	move-wide/16 v14391, v6114
	move/16 v27101, v8817
	move/16 v19699, v19856
	move-object/16 v17524, v21868
	move/16 v2698, v26480
	move/16 v7630, v1
	move/16 v25063, v32238
	move/16 v11517, v21702
	move-object/16 v30290, v32547
	move/16 v28332, v2896
	move/16 v30781, v24407
	move-wide/16 v1973, v10140
	move/16 v1141, v18986
	move/16 v8256, v10648
	move-wide/16 v29511, v29381
	move-wide/16 v27642, v3932
	move-wide/16 v26233, v32772
	move/16 v28060, v21702
	move-wide/16 v26273, v1523
	move/16 v7627, v16026
	move-wide/16 v5248, v4290
	move-wide/16 v16769, v21369
	move-object/16 v32155, v21868
	move/16 v3086, v31442
	move-object/16 v32253, v32547
	move/16 v1184, v14005
	move/16 v7637, v2900
	move/16 v28871, v30759
	move-wide/16 v24407, v2285
	move-wide/16 v11211, v5517
	move-wide/16 v6709, v27422
	move-wide/16 v16639, v10534
	move-wide/16 v10924, v14391
	move/16 v6405, v7534
	move/16 v32193, v32771
	move/16 v7058, v24327
	move-wide/16 v8000, v4651
	move/16 v2195, v2900
	move/16 v8303, v8574
	move-object/16 v2656, v9249
	move/16 v23698, v7630
	move-wide/16 v16340, v515
	move/16 v2220, v21981
	move/16 v6124, v17971
	move/16 v15558, v5452
	move/16 v6577, v16429
	move/16 v23618, v21981
	move/16 v22078, v3725
	move-wide/16 v12754, v4651
	move-wide/16 v20792, v14219
	move/16 v23423, v26480
	move/16 v18734, v30781
	move-wide/16 v27869, v10157
	move/16 v12717, v27717
	move/16 v2785, v25731
	move/16 v31619, v6653
	move/16 v14862, v17659
	move-object/16 v8481, v13702
	move-object/16 v9265, v6654
	move/16 v21677, v18486
	move/16 v6096, v2247
	move-wide/16 v27794, v10564
	move-wide/16 v23600, v17396
	move-object/16 v27464, v21868
	move/16 v21344, v5841
	move-wide/16 v11521, v515
	move/16 v3978, v1186
	move/16 v21919, v6905
	move/16 v8897, v19164
	move-object/16 v28548, v32728
	move/16 v19126, v5583
	move/16 v7056, v32020
	move-wide/16 v20386, v20792
	move/16 v812, v6517
	move-wide/16 v31442, v30069
	move-object/16 v28148, v28205
	move/16 v1106, v2492
	move-wide/16 v2993, v15544
	move-wide/16 v27382, v30779
	move-object/16 v26829, v13702
	move-wide/16 v15685, v6087
	move-object/16 v32333, v5981
	move/16 v12183, v29187
	move/16 v29287, v29003
	move-wide/16 v3840, v19825
	move/16 v22293, v15761
	move/16 v4934, v24432
	move/16 v12164, v27471
	move/16 v24380, v22293
	move-wide/16 v11355, v1973
	move/16 v12965, v30056
	move-wide/16 v28143, v28811
	move-wide/16 v24420, v19496
	move-wide/16 v29823, v15166
	move/16 v2976, v28609
	move/16 v783, v23812
	move/16 v8264, v17943
	move-wide/16 v8054, v11832
	move/16 v16739, v1141
	move-wide/16 v11219, v1095
	move/16 v1054, v25731
	move-wide/16 v2195, v28143
	move/16 v15612, v16335
	move/16 v11166, v21306
	move/16 v7970, v6405
	move/16 v19844, v7630
	move/16 v3946, v23160
	move/16 v23265, v32158
	move-object/16 v6382, v9249
	move/16 v12557, v32238
	move-object/16 v7935, v2900
	move-wide/16 v25010, v28720
	move/16 v4248, v10772
	move/16 v20237, v14510
	move-wide/16 v20123, v4736
	move/16 v25846, v26741
	move/16 v19429, v1713
	move-object/16 v11928, v28205
	move/16 v7393, v8633
	move-wide/16 v13029, v20067
	move-wide/16 v28351, v31523
	move/16 v11240, v28469
	move/16 v7930, v6653
	move-wide/16 v25104, v25814
	move-wide/16 v22908, v12966
	move-object/16 v10641, v6654
	move/16 v5943, v11064
	move-wide/16 v6974, v22688
	move/16 v25924, v14040
	move-wide/16 v26590, v3274
	move-wide/16 v2953, v14783
	move-wide/16 v10952, v25104
	move-wide/16 v17562, v27869
	move/16 v31278, v14804
	move/16 v6300, v20836
	move/16 v7169, v1713
	move/16 v4947, v18289
	move/16 v946, v21276
	move-wide/16 v6081, v11832
	move/16 v32051, v8574
	move/16 v14493, v5541
	move/16 v152, v23459
	move-object/16 v3491, v8699
	move-wide/16 v24950, v27794
	move-wide/16 v14582, v1971
	move-wide/16 v176, v19825
	move-object/16 v17437, v2093
	move-object/16 v32559, v24503
	move-wide/16 v5390, v2953
	move-wide/16 v9644, v5774
	move/16 v20863, v29736
	move-wide/16 v29928, v7177
	move-wide/16 v24499, v15617
	move-wide/16 v19301, v28590
	move/16 v30576, v6096
	move/16 v23830, v5600
	move-object/16 v19115, v27545
	move/16 v9001, v11064
	move-wide/16 v2777, v7674
	move/16 v12596, v31900
	move/16 v29684, v2785
	move/16 v7356, v28871
	move-wide/16 v19830, v28718
	move/16 v22459, v27625
	move-wide/16 v9831, v26226
	move/16 v16894, v19844
	move/16 v10188, v22459
	move/16 v1033, v27717
	move-object/16 v25651, v5372
	move/16 v1481, v152
	move-wide/16 v19103, v14065
	move/16 v14493, v12965
	move/16 v3884, v6405
	move/16 v2182, v6517
	move/16 v10341, v6653
	move/16 v10229, v29249
	move/16 v30781, v18722
	move-wide/16 v17886, v5248
	move-wide/16 v3973, v6010
	move-wide/16 v5959, v28351
	move/16 v4908, v7819
	move/16 v27373, v26502
	move/16 v14535, v3884
	move/16 v12302, v13865
	move-object/16 v3192, v3491
	move-object/16 v293, v24925
	move/16 v2976, v24824
	move-object/16 v14936, v30227
	move/16 v29344, v29704
	move/16 v22459, v15998
	move/16 v19643, v24664
	move/16 v6646, v2497
	move-object/16 v28648, v23812
	move/16 v453, v18486
	move/16 v32308, v2147
	move-wide/16 v11744, v27584
	move/16 v1386, v24432
	move/16 v15265, v7819
	move-wide/16 v29780, v1095
	move-wide/16 v11458, v23436
	move/16 v21893, v3651
	move-object/16 v10645, v28205
	move/16 v16553, v14876
	move-wide/16 v32225, v10564
	move-wide/16 v24955, v32572
	move-object/16 v7113, v17524
	move-wide/16 v11788, v24893
	move-wide/16 v16739, v31523
	move/16 v4077, v31598
	move-wide/16 v6427, v24193
	move/16 v18786, v18486
	move-wide/16 v31900, v28351
	move-wide/16 v31071, v17999
	move-wide/16 v14659, v27642
	move-object/16 v8289, v31286
	move-wide/16 v4887, v24193
	move/16 v4220, v6690
	move/16 v4018, v23618
	move-wide/16 v29004, v20792
	move/16 v6862, v8264
	move-wide/16 v31441, v26105
	move/16 v20794, v15998
	move/16 v23109, v5541
	move-wide/16 v4462, v29024
	move-wide/16 v8209, v14871
	move/16 v10531, v14040
	move/16 v31859, v32333
	move/16 v27495, v25118
	move-object/16 v26068, v30290
	move-wide/16 v22552, v10924
	move/16 v28357, v32158
	move/16 v30734, v20237
	move/16 v20119, v12478
	move-object/16 v30057, v32728
	move/16 v15122, v5943
	move/16 v24031, v5583
	move-wide/16 v2071, v26350
	move-wide/16 v12715, v32632
	move-wide/16 v17169, v15443
	move/16 v5086, v4934
	move/16 v13906, v5924
	move/16 v27161, v5467
	move-object/16 v31089, v15170
	move-object/16 v11982, v2656
	move-object/16 v4540, v11409
	move/16 v14339, v16372
	move-wide/16 v17749, v2195
	move/16 v25542, v5583
	move/16 v25831, v25073
	move/16 v14749, v23283
	move/16 v13281, v31859
	move-wide/16 v3705, v28578
	move/16 v3413, v20863
	move/16 v28578, v4540
	move-object/16 v4031, v28148
	move-wide/16 v13267, v29004
	move/16 v15849, v30594
	move/16 v7303, v27101
	move-wide/16 v11879, v24499
	move-wide/16 v21736, v24038
	move-wide/16 v18138, v14562
	move-wide/16 v1753, v16739
	move/16 v17538, v5086
	move/16 v9384, v4077
	move-wide/16 v12937, v14562
	move/16 v18130, v29526
	move/16 v7372, v19429
	move/16 v11662, v29287
	move/16 v18033, v12557
	move-object/16 v26631, v5181
	move-wide/16 v240, v16632
	move/16 v3585, v10800
	move/16 v10531, v32061
	move-wide/16 v14434, v7914
	move-object/16 v19429, v31089
	move/16 v1769, v12032
	move-wide/16 v1732, v10716
	move-wide/16 v4993, v1109
	move/16 v924, v8481
	move/16 v23883, v8761
	move-wide/16 v12937, v11832
	move-object/16 v7450, v19856
	move/16 v4258, v7372
	move-wide/16 v24669, v23105
	move/16 v5600, v8897
	move/16 v31807, v16335
	move/16 v30779, v2492
	move-wide/16 v26669, v7440
	move-wide/16 v28609, v19830
	move-wide/16 v18041, v4925
	move/16 v15849, v6653
	move-wide/16 v6741, v19830
	move/16 v11928, v12826
	move-wide/16 v5193, v32572
	move/16 v19312, v6298
	move-object/16 v24296, v5181
	move/16 v1529, v24327
	move-wide/16 v30790, v4290
	move/16 v10698, v5086
	move/16 v21138, v15265
	move-object/16 v29725, v15170
	move/16 v14026, v32708
	move/16 v7754, v6653
	move-wide/16 v22315, v9644
	move/16 v14276, v24031
	move-object/16 v22611, v836
	move/16 v9318, v9194
	move/16 v4001, v5086
	move-wide/16 v10341, v12937
	move/16 v32093, v24422
	move/16 v28223, v7534
	move/16 v11057, v4668
	move/16 v26796, v11057
	move-wide/16 v7254, v17396
	move/16 v23997, v28332
	move-wide/16 v7970, v15544
	move-object/16 v7794, v4031
	move/16 v22937, v16352
	move/16 v11332, v16352
	move/16 v18802, v3978
	move/16 v10353, v14993
	move/16 v4805, v15849
	move-wide/16 v18564, v26669
	move-object/16 v13340, v27545
	move-object/16 v21276, v11166
	move-wide/16 v17348, v16380
	move/16 v28449, v29187
	move/16 v27277, v24788
	move-object/16 v19562, v28386
	move/16 v9764, v17943
	move/16 v29559, v5841
	move-object/16 v240, v836
	move/16 v22523, v30446
	move/16 v17865, v16933
	move-wide/16 v5866, v11376
	move-wide/16 v4388, v23105
	move/16 v9065, v8649
	move/16 v1938, v1
	move/16 v29276, v24273
	move/16 v18226, v959
	move/16 v10032, v24422
	move-wide/16 v1033, v16055
	move/16 v2907, v32093
	move-wide/16 v10411, v28811
	move/16 v26564, v25808
	move-wide/16 v22517, v1415
	move-object/16 v6049, v30290
	move-object/16 v10012, v7794
	move/16 v20985, v14493
	move/16 v21538, v30759
	move/16 v23754, v23264
	move/16 v2009, v26564
	move-wide/16 v5952, v24038
	move-wide/16 v7990, v31441
	move-wide/16 v677, v28351
	move/16 v14535, v25846
	move-wide/16 v31034, v4290
	move-object/16 v19613, v31089
	move/16 v29418, v22238
	move-object/16 v24357, v10645
	move/16 v27130, v15690
	move/16 v10045, v20860
	move/16 v6100, v15558
	move-wide/16 v30838, v31304
	move/16 v28386, v14493
	move-wide/16 v7205, v14579
	move-object/16 v15906, v293
	move-object/16 v15298, v30535
	move/16 v27869, v23618
	move-wide/16 v7002, v18170
	move/16 v18972, v6241
	move-wide/16 v16947, v16739
	move-wide/16 v10676, v11744
	move/16 v4875, v9384
	move/16 v9336, v23997
	move/16 v25857, v5467
	move/16 v3946, v18204
	move-wide/16 v7626, v8209
	move/16 v208, v8264
	move/16 v22764, v22776
	move/16 v3939, v30772
	move/16 v10380, v19115
	move/16 v12537, v17217
	move-wide/16 v783, v23185
	move-wide/16 v3297, v15544
	move-object/16 v13263, v4524
	move-wide/16 v12113, v18041
	move/16 v30728, v1386
	move/16 v24726, v7372
	move-wide/16 v24499, v32772
	move/16 v14013, v12717
	move-wide/16 v19690, v24669
	move/from16 v132, v18929
	move-object/16 v923, v19115
	move/16 v27331, v24273
	move/16 v26563, v11916
	move-object/16 v19735, v117
	move-wide/16 v150, v28590
	move/16 v15375, v28060
	move/16 v27376, v15375
	move/16 v28713, v32774
	move-object/16 v19262, v15170
	move/16 v18348, v20860
	move/16 v19048, v1529
	move/16 v7819, v28223
	move/16 v3974, v29187
	move-wide/16 v21702, v17169
	move/16 v16891, v30734
	move-wide/16 v27352, v18170
	move/16 v21806, v23160
	move-wide/16 v12855, v14582
	move-object/16 v14396, v27464
	move/16 v19891, v15761
	move-wide/16 v1621, v8054
	move/16 v19136, v4248
	move/16 v6415, v1983
	move/16 v17095, v1481
	move-wide/16 v8149, v10370
	move-object/16 v28143, v16169
	move/16 v23066, v16553
	move-wide/16 v27545, v27642
	move/16 v17401, v23880
	move/16 v6115, v17217
	move-wide/16 v3840, v2104
	move-wide/16 v5354, v26233
	move-wide/16 v16877, v23600
	move/16 v31029, v32771
	move/16 v28129, v16891
	move-object/16 v16430, v32547
	move/16 v26330, v3651
	move/16 v1735, v31696
	move/16 v31789, v30056
	move-wide/16 v5732, v16403
	move-object/16 v21542, v22773
	move-object/16 v24919, v30290
	move/16 v3418, v27717
	move/16 v7022, v32627
	move-wide/16 v28734, v24193
	move-object/16 v488, v3175
	move-object/16 v23252, v14396
	move/16 v18587, v15849
	move-object/16 v6690, v14328
	move/16 v12474, v5629
	move-wide/16 v10151, v14391
	move-wide/16 v15451, v7073
	move-wide/16 v9403, v20067
	move-object/16 v727, v26741
	move/16 v13944, v1106
	move/16 v26973, v22392
	move-object/16 v19600, v2656
	move-object/16 v25282, v4947
	move/16 v19639, v21573
	move-object/16 v2515, v16430
	move-wide/16 v21670, v2104
	move/16 v9033, v5981
	move/16 v15170, v21573
	move/16 v27640, v6382
	move-wide/16 v22392, v1095
	move/16 v27344, v17971
	move-object/16 v3296, v6049
	move/16 v10012, v7169
	move/16 v3475, v15998
	move-wide/16 v5732, v15451
	move/16 v5808, v13263
	move-object/16 v18267, v11166
	move/16 v7838, v32428
	move-wide/16 v14625, v8054
	move-wide/16 v10645, v6427
	move-object/16 v21563, v25135
	move-wide/16 v24091, v20531
	move-wide/16 v453, v6087
	move/16 v28909, v6577
	move/16 v4970, v18378
	move/16 v25819, v3679
	move/16 v20711, v21677
	move/16 v26003, v20711
	move-wide/16 v3064, v14582
	move/16 v5282, v29433
	move/16 v11711, v19048
	move/16 v6790, v25831
	move-wide/16 v10941, v11879
	move-wide/16 v14685, v18564
	move-wide/16 v23862, v11355
	move-object/16 v31334, v23883
	move/16 v19060, v17659
	move/16 v14633, v19541
	move/16 v10041, v24432
	move-wide/16 v28275, v18041
	move-wide/16 v21755, v2285
	move/16 v8216, v7450
	move/16 v16751, v26631
	move/16 v30515, v26563
	move-object/16 v6584, v29725
	move-wide/16 v3303, v2104
	move-wide/16 v6669, v15166
	move-object/16 v29565, v28143
	move-object/16 v23441, v21542
	move-wide/16 v4855, v13267
	move-object/16 v12230, v9249
	move-wide/16 v774, v25010
	move-object/16 v14337, v2900
	move-wide/16 v11710, v28590
	move-wide/16 v26047, v26273
	move/16 v31872, v18374
	move-object/16 v15925, v26898
	move-wide/16 v11861, v25340
	move-wide/16 v9477, v13029
	move/16 v3875, v924
	move-wide/16 v29992, v1109
	move-wide/16 v8483, v2104
	move-wide/16 v17211, v17886
	move-wide/16 v28357, v24038
	move-wide/16 v28767, v13775
	move-wide/16 v3869, v17886
	move-object/16 v17943, v924
	move/16 v19559, v11517
	move/16 v14177, v10648
	move/16 v18843, v20794
	move-wide/16 v29288, v27382
	move/16 v9104, v2894
	move-wide/16 v21989, v11879
	move-wide/16 v4875, v31071
	move-wide/16 v29400, v18387
	move-object/16 v21577, v19562
	move-object/16 v29511, v6584
	move/16 v20202, v22078
	move/16 v19004, v30905
	move-wide/16 v16748, v29024
	move/16 v19828, v26330
	move/16 v6470, v18348
	move-wide/16 v32730, v14579
	move/16 v6245, v27869
	move/16 v10839, v26829
	move-object/16 v4804, v24357
	move/16 v6979, v12478
	move-wide/16 v6374, v29400
	move/16 v19226, v11197
	move-object/16 v28129, v3672
	move-wide/16 v29324, v15685
	move-object/16 v24643, v10641
	move/16 v14650, v25470
	move-wide/16 v12395, v11355
	move/16 v501, v5943
	move-object/16 v16552, v17215
	move-wide/16 v15951, v1033
	move/16 v10221, v12302
	move-wide/16 v23975, v14685
	move-object/16 v18036, v26161
	move/16 v15476, v2247
	move/16 v9271, v4453
	move/16 v13728, v22937
	move-object/16 v5575, v26631
	move/16 v29172, v28469
	move/16 v21866, v14876
	move-wide/16 v597, v21454
	move-wide/16 v27892, v11788
	move-wide/16 v22523, v2
	move-wide/16 v20931, v22392
	move-object/16 v15139, v28129
	move/16 v21935, v18267
	move/16 v27228, v21806
	move-wide/16 v27735, v27382
	move-wide/16 v6879, v10370
	move/16 v2515, v29344
	move/16 v27723, v6096
	move/16 v12042, v21866
	move/16 v20992, v3940
	move-object/16 v18564, v872
	move/16 v28882, v7629
	move-wide/16 v14877, v14579
	move-wide/16 v6123, v7143
	move/16 v23082, v32028
	move/16 v3145, v14040
	move/16 v28723, v2147
	move/16 v10165, v23082
	move-object/16 v18630, v14936
	move/16 v23713, v24664
	move-object/16 v30639, v28548
	move-wide/16 v14477, v31304
	move-wide/16 v523, v2071
	move-wide/16 v12501, v28590
	move/16 v17048, v32627
	move-object/16 v852, v27410
	move-object/16 v138, v19115
	move-wide/16 v19550, v19585
	move/16 v10476, v6517
	move-wide/16 v4327, v1084
	move/16 v19974, v16891
	move/16 v19102, v12478
	move/16 v6255, v24432
	move/16 v25135, v21580
	move-object/16 v11384, v10641
	move-wide/16 v1716, v6123
	move-wide/16 v18999, v2993
	move/16 v10894, v3939
	move-wide/16 v4429, v29163
	move/16 v12745, v19891
	move/16 v16196, v20985
	move-object/16 v8685, v17599
	move/16 v6277, v24031
	move/16 v19559, v2515
	move/16 v30356, v27625
	move/16 v4253, v18972
	move/16 v24912, v10041
	move-object/16 v12554, v5635
	move/16 v22168, v19048
	move/16 v32768, v14013
	move/16 v8158, v3651
	move-wide/16 v25746, v14783
	move-wide/16 v28922, v23105
	move/16 v26024, v7838
	move/16 v19989, v12826
	move/16 v25880, v10531
	move/16 v6298, v30759
	move-wide/16 v26003, v16947
	move-wide/16 v4603, v17999
	move-wide/16 v30298, v23688
	move/16 v9582, v7372
	move-wide/16 v8224, v2071
	move-wide/16 v29762, v20420
	move/16 v19541, v19998
	move/16 v23511, v11928
	move/16 v19825, v29418
	move/16 v4859, v20202
	move/16 v10265, v10045
	move-object/16 v16941, v28548
	move-object/16 v15378, v17876
	move/16 v26024, v7118
	move/16 v7956, v18587
	move-wide/16 v6305, v7443
	move/16 v29254, v9271
	move-wide/16 v5706, v20644
	move/16 v16360, v6690
	move-wide/16 v30981, v28922
	move-wide/16 v12184, v6974
	move/16 v16909, v20863
	move-wide/16 v6065, v5390
	move/16 v9751, v20596
	move/16 v5137, v18722
	move-object/16 v20838, v23992
	move/16 v23651, v25957
	move/16 v15685, v8633
	move-wide/16 v2800, v1084
	move/16 v19237, v19825
	move-object/16 v14024, v32559
	move-wide/16 v4319, v21454
	move/16 v14806, v24380
	move/16 v32625, v4668
	move-object/16 v17524, v32051
	move/16 v18642, v3672
	move-wide/16 v5583, v19496
	move/16 v4906, v29526
	move-wide/16 v11935, v29992
	move/16 v4031, v30779
	move-object/16 v4479, v25282
	move/16 v1694, v18802
	move-object/16 v12611, v7113
	move-wide/16 v19914, v4993
	move/16 v22731, v2913
	move-object/16 v20253, v3175
	move-wide/16 v7000, v4462
	move-wide/16 v8415, v2071
	move/16 v26161, v3145
	move/16 v18641, v3940
	move-wide/16 v14616, v2777
	move-wide/16 v27584, v16340
	move/16 v15085, v21677
	move/16 v20482, v6300
	move-wide/16 v4036, v16739
	move-wide/16 v12826, v453
	move/16 v6257, v1184
	move-wide/16 v18610, v14659
	move/16 v21289, v11200
	move-wide/16 v30752, v6065
	move-wide/16 v13483, v26105
	move-object/16 v10688, v19562
	move/16 v29163, v9764
	move-object/16 v15584, v28205
	move-object/16 v6961, v19262
	move/16 v9032, v30734
	move/16 v5331, v16429
	move-wide/16 v25251, v16403
	move-object/16 v30406, v22773
	move/16 v1811, v18986
	move/16 v5473, v11662
	move-wide/16 v2001, v5866
	move-wide/16 v16192, v14065
	move/16 v28825, v3475
	move-wide/16 v29811, v2195
	move/16 v4487, v25808
	move-wide/16 v31553, v26226
	move/16 v19899, v27471
	move-wide/16 v6826, v22688
	move-wide/16 v31885, v15617
	move/16 v1025, v10737
	move/16 v1529, v25857
	move-object/16 v23105, v7976
	move/16 v29368, v32238
	move-wide/16 v7818, v14625
	move-wide/16 v2697, v12826
	move-object/16 v19065, v24643
	move/16 v12506, v18986
	move-wide/16 v20985, v21702
	move/16 v20660, v10772
	move-object/16 v18417, v24787
	move-object/16 v11879, v4479
	move-object/16 v20691, v5808
	move-wide/16 v27838, v19914
	move/16 v15960, v16429
	move/16 v32196, v15265
	move-wide/16 v28982, v4429
	move-wide/16 v20505, v9477
	move/16 v24100, v152
	move/16 v30728, v23698
	move-wide/16 v19652, v5517
	move/16 v17505, v10648
	move-wide/16 v24166, v21702
	move-object/16 v2431, v8685
	move-wide/16 v3651, v29004
	move/16 v1386, v2656
	move-wide/16 v27211, v2953
	move/16 v14413, v29249
	move-wide/16 v22785, v15166
	move/16 v31900, v5635
	move/16 v1523, v11875
	move-wide/16 v25572, v19652
	move/16 v553, v29003
	move-object/16 v26794, v21563
	move/16 v26885, v7629
	move/16 v21342, v29054
	move/16 v16611, v3585
	move/16 v21135, v19856
	move/16 v12190, v13381
	move/16 v18388, v11332
	move/16 v21984, v32363
	move-object/16 v28825, v19613
	move/16 v7744, v29287
	move/16 v26899, v15925
	move-wide/16 v28285, v11935
	move/16 v4290, v29172
	move/16 v5374, v553
	move-object/16 v22238, v11384
	move/16 v10551, v4258
	move-wide/16 v26436, v16055
	move-wide/16 v31155, v15443
	move-object/16 v4255, v8574
	move/16 v11788, v29526
	move/16 v21369, v4548
	move/16 v16579, v6470
	move/16 v27708, v24912
	move-wide/16 v27907, v26047
	move-object/16 v6315, v11982
	move-object/16 v25838, v30057
	move-wide/16 v1386, v3064
	move/16 v13527, v27228
	move-wide/16 v4388, v30298
	move-wide/16 v6974, v31441
	move/16 v13158, v16909
	move-wide/16 v26794, v14562
	move/16 v22082, v16553
	move-wide/16 v21559, v16639
	move/16 v6896, v9336
	move-object/16 v4197, v27366
	move-wide/16 v10157, v17348
	move-wide/16 v10732, v26105
	move-wide/16 v26471, v16380
	move-wide/16 v25696, v20386
	move/16 v9735, v19559
	move-wide/16 v21398, v476
	move-wide/16 v7062, v22523
	move/16 v12028, v13527
	move-object/16 v19064, v13015
	move/16 v12249, v6096
	move/16 v18928, v3946
	move-wide/16 v28187, v31523
	move/16 v20007, v1713
	move/16 v20418, v28049
	move-object/16 v1922, v24357
	move/16 v19735, v10551
	move/16 v1579, v29344
	move-object/16 v27322, v19613
	move-wide/16 v8388, v8000
	move-wide/16 v6498, v16769
	move/16 v6442, v23066
	move-wide/16 v10272, v29347
	move/16 v19861, v31981
	move-wide/16 v17749, v29992
	move-wide/16 v4915, v6879
	move-wide/16 v671, v4651
	move-object/16 v8329, v24296
	move-wide/16 v14609, v22738
	move/16 v1490, v30611
	move-wide/16 v16366, v6427
	move/16 v25007, v28713
	move-object/16 v27983, v3175
	move-object/16 v4150, v7450
	move-wide/16 v4495, v20420
	move-wide/16 v24486, v10157
	move-object/16 v14401, v10439
	move/16 v18968, v22293
	move-object/16 v22158, v8289
	move/from16 v252, v5374
	move/16 v6406, v15612
	move-object/16 v29627, v4524
	move-wide/16 v4557, v2285
	move-wide/16 v19161, v29762
	move/16 v15375, v20794
	move/16 v15558, v6442
	move-wide/16 v22761, v27735
	move/16 v7754, v23698
	move/16 v8879, v959
	move/16 v17029, v1529
	move/16 v32179, v14862
	move/16 v21563, v6646
	move/16 v24718, v13476
	move/16 v23660, v7428
	move/16 v16932, v23874
	move-wide/16 v12221, v453
	move-object/16 v6675, v8685
	move/16 v13381, v20691
	move/16 v16691, v18928
	move/16 v19296, v28713
	move-object/16 v29117, v23992
	move/16 v19058, v18289
	move-wide/16 v17864, v5952
	move-wide/16 v13677, v15451
	move-wide/16 v18294, v3064
	move/16 v25828, v16335
	move/16 v23653, v132
	move-wide/16 v26841, v16366
	move-wide/16 v20224, v20034
	move-wide/16 v14339, v6081
	move-object/16 v29870, v7319
	move-object/16 v4934, v16941
	move-wide/16 v6581, v4736
	move/16 v7499, v30772
	move-wide/16 v27787, v7440
	move/16 v26113, v32238
	move-wide/16 v7385, v7990
	move/16 v29803, v31240
	move/16 v11445, v14413
	move-wide/16 v10525, v28590
	move/16 v29649, v21981
	move/16 v9104, v14650
	move-wide/16 v27479, v20931
	move/16 v19858, v26885
	move-object/16 v4540, v6748
	move/16 v7974, v10353
	move/16 v29059, v21573
	move/16 v4432, v20794
	move-object/16 v17991, v19600
	move-wide/16 v23026, v20644
	move/16 v6738, v15476
	move/16 v31096, v18734
	move/16 v5104, v23812
	move/16 v22101, v20103
	move/16 v22776, v21893
	move/16 v14519, v31789
	move-object/16 v26096, v22611
	move-wide/16 v29482, v9403
	move/16 v19165, v10551
	move-object/16 v8000, v352
	move-object/16 v8818, v14024
	move/16 v30666, v30446
	move-wide/16 v32772, v2777
	move-object/16 v22256, v30406
	move-object/16 v21464, v22611
	move-wide/16 v6347, v27479
	move-object/16 v10486, v23252
	move/16 v487, v25135
	move-wide/16 v5279, v2195
	move/16 v5650, v22168
	move/16 v7641, v20711
	move-object/16 v3145, v10032
	move/16 v8526, v15085
	move-wide/16 v15925, v11211
	move/16 v32768, v18786
	move-object/16 v523, v19115
	move/16 v6218, v4487
	move-wide/16 v22422, v20224
	move/16 v29054, v16092
	move-wide/16 v9644, v11376
	move-wide/16 v1676, v23600
	move-object/16 v6879, v26829
	move/16 v28911, v19115
	move-wide/16 v7122, v24669
	move/16 v31194, v21138
	move-wide/16 v29937, v10924
	move-object/16 v1600, v924
	move-wide/16 v24703, v21398
	move-object/16 v6277, v19262
	move-object/16 v28748, v8818
	move-object/16 v3890, v8289
	move/16 v15834, v2497
	move/16 v10732, v13944
	move-object/16 v30105, v32767
	move/16 v677, v32428
	move-wide/16 v16026, v18610
	move-object/16 v31499, v30105
	move-wide/16 v26371, v12395
	move/16 v21182, v31807
	move-wide/16 v27331, v30981
	move-object/16 v10958, v16169
	move-wide/16 v11556, v21670
	move/16 v23562, v18130
	move-object/16 v12461, v3548
	move-wide/16 v31564, v22738
	move-wide/16 v12689, v9831
	move/16 v7620, v8918
	move-object/16 v17528, v22101
	move/16 v29627, v29704
	move/16 v19365, v4432
	move-object/16 v3735, v31900
	move/16 v26795, v28882
	move/16 v14245, v14161
	move-object/16 v21850, v21848
	move-wide/16 v32260, v27787
	move/16 v21538, v24031
	move/16 v26003, v25063
	move-wide/16 v3856, v26669
	move-wide/16 v24846, v7818
	move/16 v7285, v10041
	move/16 v12282, v11879
	move/16 v11269, v21563
	move/16 v24011, v25135
	move-wide/16 v2907, v13029
	move-wide/16 v31071, v23839
	move/16 v9360, v17505
	move/16 v22872, v29254
	move-wide/16 v3296, v19652
	move-wide/16 v20712, v11458
	move-wide/16 v13279, v2195
	move-wide/16 v12824, v4388
	move/16 v4889, v4815
	move-wide/16 v2278, v2132
	move-wide/16 v8460, v20123
	move-wide/16 v339, v24193
	move-object/16 v2495, v924
	move/16 v4253, v15265
	move-object/16 v3559, v28129
	move/16 v24905, v16553
	move-wide/16 v17369, v4036
	move-wide/16 v10385, v23688
	move-object/16 v19643, v31499
	move-wide/16 v691, v5774
	move/16 v7449, v6382
	move/16 v30742, v22764
	move-object/16 v2060, v4524
	move/16 v6714, v6298
	move-wide/16 v8353, v9831
	move/16 v31597, v29684
	move/16 v14062, v21369
	move-wide/16 v5959, v26226
	move-wide/16 v4819, v14537
	move/16 v28075, v8158
	move-wide/16 v26050, v21559
	move-wide/16 v32074, v27735
	move-wide/16 v22780, v15201
	move-object/16 v899, v15584
	move-wide/16 v2711, v12501
	move/16 v1222, v27671
	move-wide/16 v27697, v8460
	move/16 v7285, v4970
	move/16 v11933, v2009
	move/16 v17506, v31566
	move-wide/16 v14853, v14625
	move-wide/16 v3940, v10564
	move/16 v28430, v14026
	move-wide/16 v14957, v18170
	move/16 v26093, v3974
	move-wide/16 v31185, v23862
	move/16 v10081, v18642
	move/16 v22611, v22082
	move-wide/16 v8533, v19301
	move-wide/16 v20644, v29400
	move/16 v16968, v9735
	move-wide/16 v4307, v4462
	move-wide/16 v27997, v20644
	move/16 v18118, v21563
	move-wide/16 v17956, v19830
	move/16 v13808, v28060
	move-wide/16 v12004, v28982
	move/16 v26259, v10772
	move-wide/16 v27065, v150
	move-object/16 v4548, v31089
	move-object/16 v6039, v7794
	move-wide/16 v2896, v4887
	move/16 v3559, v12302
	move/16 v11770, v30594
	move-object/16 v23781, v32093
	move/16 v32275, v19899
	move-wide/16 v4561, v15544
	move/16 v12001, v7838
	move-wide/16 v23337, v22517
	move/16 v14213, v11445
	move/16 v9623, v29054
	move/16 v756, v10737
	move/16 v2136, v4839
	move-object/16 v20794, v11409
	move/16 v17802, v5650
	move-wide/16 v10841, v3064
	move-wide/16 v19193, v3840
	move/16 v1198, v23264
	move/16 v27458, v21344
	move-wide/16 v31660, v10525
	move-wide/16 v11079, v6669
	move-object/16 v28999, v14401
	move-wide/16 v31334, v13279
	move-wide/16 v20460, v28285
	move-wide/16 v21580, v9644
	move/16 v23309, v14245
	move/16 v29762, v21677
	move-object/16 v21270, v4540
	move/16 v31887, v1523
	move/16 v31336, v6790
	move/16 v25367, v3725
	move-wide/16 v32760, v12826
	move-object/16 v23578, v26844
	move/16 v17747, v29649
	move/16 v29765, v3672
	move/16 v17217, v6517
	move-wide/16 v7301, v28187
	move-object/16 v22177, v5575
	move-wide/16 v2071, v22785
	move-wide/16 v5376, v7990
	move-wide/16 v26549, v17396
	move-wide/16 v24327, v6123
	move-wide/16 v23968, v27697
	move/16 v3012, v4839
	move/16 v23559, v26564
	move-wide/16 v5840, v28609
	move/16 v7630, v2479
	move-object/16 v12506, v28825
	move/16 v19102, v27458
	move-wide/16 v1368, v339
	move/16 v30270, v2147
	move-object/16 v10822, v23252
	move/16 v6714, v30728
	move-wide/16 v5863, v6179
	move/16 v30945, v30759
	move/16 v19961, v16891
	move/16 v18462, v2492
	move/16 v25703, v21369
	move-wide/16 v15805, v6741
	move/16 v10320, v7372
	move/16 v31062, v14749
	move/16 v16788, v30666
	move-wide/16 v16908, v12395
	move/16 v3019, v2497
	move-wide/16 v2811, v19161
	move-wide/16 v16901, v1415
	move-wide/16 v17896, v8224
	move-wide/16 v25913, v3856
	move/16 v1102, v11200
	move-wide/16 v10621, v27584
	move-wide/16 v28317, v2896
	move/16 v29153, v7838
	move/16 v30874, v10041
	move-object/16 v31337, v32117
	move-object/16 v14177, v18641
	move/16 v10389, v32092
	move/16 v1638, v10353
	move/16 v16055, v12971
	move-wide/16 v10990, v29400
	move/16 v28457, v19861
	move-wide/16 v26472, v16748
	move-wide/16 v872, v14625
	move/16 v31807, v2182
	move-object/16 v3308, v10822
	move/16 v4307, v6241
	move/16 v5174, v20691
	move-wide/16 v10743, v14685
	move-wide/16 v10219, v20505
	move-object/16 v19856, v19065
	move/16 v27654, v1811
	move/16 v11636, v14467
	move/16 v30694, v1198
	move/16 v6814, v5981
	move/16 v18168, v23830
	move/16 v9318, v25063
	move/16 v24383, v6896
	move-wide/16 v24977, v15201
	move-object/16 v10684, v21577
	move-object/16 v31618, v30227
	move-object/16 v9751, v240
	move/16 v17710, v20482
	move-wide/16 v20860, v6347
	move-wide/16 v23225, v12689
	move/16 v8057, v8649
	move/16 v9806, v6096
	move/16 v8777, v19861
	move-object/16 v9806, v30227
	move-wide/16 v10157, v27331
	move/16 v28181, v23651
	move-wide/16 v5433, v14579
	move-wide/16 v14815, v23600
	move-wide/16 v7483, v10645
	move/16 v14387, v23830
	move-wide/16 v5583, v150
	move/16 v4568, v14633
	move/16 v10012, v10265
	move-object/16 v30765, v3548
	move/16 v13340, v20711
	move/16 v11928, v11879
	move-object/16 v25470, v23105
	move/16 v12222, v28882
	move/16 v16649, v6405
	move/16 v15593, v2785
	move/16 v15523, v24912
	move/16 v26474, v18033
	move-wide/16 v21344, v25814
	move-wide/16 v31419, v20034
	move-object/16 v26516, v26898
	move/16 v3357, v29287
	move-object/16 v4934, v8289
	move/16 v29565, v487
	move/16 v21819, v32179
	move/16 v8508, v6115
	move/16 v31691, v7372
	move/16 v3157, v5137
	move-wide/16 v18342, v6498
	move/16 v28401, v4487
	move/16 v19989, v31400
	move-wide/16 v28260, v32760
	move-wide/16 v7022, v18342
	move/16 v12142, v16552
	move-object/16 v26879, v25470
	move/16 v3783, v6470
	move/16 v14783, v4970
	move/16 v924, v11269
	move/16 v26373, v30772
	move/16 v15179, v11269
	move-wide/16 v30022, v339
	move-wide/16 v19917, v12826
	move/16 v2896, v14013
	move-wide/16 v13593, v17562
	move/16 v13569, v27495
	move-object/16 v18610, v29117
	move-wide/16 v18481, v27382
	move-wide/16 v31807, v31439
	move-wide/16 v23124, v18342
	move/16 v15787, v30270
	move/16 v3684, v6255
	move-object/16 v20153, v852
	move/16 v21258, v9271
	move/16 v22445, v29704
	move-wide/16 v14024, v26436
	move/16 v20237, v9623
	move/16 v14177, v18843
	move-wide/16 v4603, v4036
	move/16 v29360, v32179
	move/16 v16295, v10320
	move/16 v9353, v6026
	move/16 v1694, v10221
	move/16 v15659, v9764
	move/16 v12252, v19312
	move/16 v501, v26093
	move-wide/16 v15446, v20034
	move/16 v22136, v727
	move-wide/16 v13238, v24327
	move-wide/16 v2593, v3856
	move-wide/16 v14001, v6741
	move/16 v8280, v4453
	move/16 v1960, v20253
	move/16 v31004, v26003
	move-wide/16 v5616, v24669
	move/16 v23686, v4018
	move/16 v28664, v28999
	move-object/16 v10110, v30105
	move/16 v27903, v2182
	move/16 v20038, v6241
	move-wide/16 v32627, v2811
	move/16 v32232, v6241
	move-wide/16 v4197, v5732
	move-wide/16 v11521, v28982
	move/16 v4487, v6241
	move-object/16 v28664, v3145
	move-object/16 v4750, v23992
	move-wide/16 v21669, v26105
	move/16 v24916, v29565
	move-wide/16 v21119, v2278
	move-wide/16 v20822, v7970
	move/16 v26068, v11662
	move/16 v27356, v20660
	move-wide/16 v14749, v4915
	move-wide/16 v6850, v11458
	move/16 v29146, v117
	move/16 v26857, v26795
	move-wide/16 v17780, v29004
	move/16 v31159, v10800
	move/16 v1600, v26973
	move/16 v23226, v1198
	move/16 v8037, v15391
	move-wide/16 v12013, v4887
	move-wide/16 v795, v4388
	move-object/16 v24128, v8761
	move-object/16 v23265, v10486
	move/16 v3087, v12164
	move/16 v17798, v18033
	move-wide/16 v20007, v26350
	move/16 v11671, v15761
	move/16 v16780, v18587
	move-wide/16 v9514, v32760
	move-wide/16 v31004, v4603
	move/16 v6790, v25135
	move-object/16 v12222, v16169
	move-wide/16 v3418, v10370
	move-wide/16 v24372, v7177
	move/16 v4194, v24664
	move-object/16 v6049, v29131
	move/16 v12910, v17401
	move/16 v23975, v21106
	move/16 v12383, v1481
	move-object/16 v445, v352
	move/16 v20860, v29559
	move-wide/16 v24846, v23436
	move-object/16 v28010, v14761
	move-object/16 v2620, v32767
	move-wide/16 v7898, v6010
	move/16 v29961, v13944
	move-object/16 v10116, v15378
	move-object/16 v516, v32253
	move-object/16 v25916, v8872
	move/16 v15670, v4258
	move-wide/16 v31742, v2001
	move/16 v757, v7056
	move/16 v1306, v2479
	move/16 v5829, v12554
	move/16 v20158, v14213
	move-wide/16 v32117, v5354
	move-wide/16 v26330, v31660
	move/16 v20218, v19559
	move-object/16 v17169, v17943
	move-wide/16 v15022, v7143
	move-wide/16 v1688, v9831
	move-wide/16 v16026, v31564
	move/16 v888, v13569
	move-wide/16 v14535, v5863
	move-object/16 v31954, v17943
	move-wide/16 v2262, v21989
	move-object/16 v3192, v23992
	move/16 v23678, v25880
	move-wide/16 v31869, v24846
	move/16 v240, v3974
	move-wide/16 v15568, v2071
	move/16 v31202, v2060
	move/16 v5706, v16894
	move-wide/16 v8516, v20931
	move-wide/16 v14783, v8388
	move/16 v19496, v32051
	move-wide/16 v18972, v20505
	move-wide/16 v14005, v28720
	move/16 v15292, v18374
	move-object/16 v28466, v445
	move/16 v271, v1735
	move/16 v24926, v30594
	move/16 v26899, v2136
	move/16 v13593, v26885
	move/16 v10924, v5541
	move-wide/16 v32186, v14685
	move/16 v6471, v16933
	move/16 v31034, v29163
	move/16 v9872, v14862
	move/16 v23596, v16553
	move-object/16 v12754, v19643
	move/16 v6661, v30594
	move/16 v27360, v15476
	move-object/16 v10580, v2656
	move/16 v25632, v9032
	move/16 v31731, v2182
	move/16 v30298, v28223
	move-wide/16 v2172, v2278
	move-wide/16 v7483, v28734
	move/16 v8774, v25542
	move/16 v32428, v27373
	move-object/16 v29017, v19562
	move/16 v10391, v26093
	move/16 v28597, v26003
	move/16 v16157, v1029
	move/16 v23592, v13728
	move/16 v30311, v4248
	move-wide/16 v1605, v5390
	move/16 v28070, v553
	move/16 v18130, v12164
	move-wide/16 v14949, v3291
	move/16 v26315, v23678
	move-wide/16 v15366, v31185
	move/16 v13164, v19844
	move/16 v16038, v9764
	move-object/16 v22828, v27410
	move/16 v12518, v26093
	move/16 v26342, v2785
	move-wide/16 v10403, v1084
	move-wide/16 v3725, v5193
	move/16 v22574, v1306
	move/16 v26885, v32308
	move/16 v27014, v29287
	move/16 v23558, v20119
	move/16 v13238, v14519
	move/16 v4925, v12965
	move-object/16 v12274, v19562
	move/16 v11710, v19974
	move/16 v16941, v16649
	move-wide/16 v1067, v16739
	move-wide/16 v5962, v27787
	move-wide/16 v27952, v27997
	move-object/16 v29615, v6315
	move/16 v31523, v17659
	move/16 v29186, v677
	move/16 v14783, v23283
	move-object/16 v18294, v6039
	move-wide/16 v23207, v24420
	move-wide/16 v20764, v26715
	move-wide/16 v10743, v2593
	move-object/16 v29288, v22256
	move-wide/16 v30714, v21454
	move/16 v22562, v13527
	move/16 v8158, v14013
	move-wide/16 v28267, v25340
	move-wide/16 v1105, v6374
	move/16 v20711, v28909
	move/16 v8209, v23686
	move-object/16 v12055, v18172
	move/16 v9865, v23592
	move/16 v11198, v15292
	move-wide/16 v23303, v9477
	move-object/16 v6065, v19613
	move-wide/16 v12458, v27907
	move/16 v15170, v3087
	move/16 v22505, v22082
	move/16 v15912, v8280
	move/16 v16277, v3559
	move-wide/16 v11438, v31071
	move/16 v18419, v27360
	move/16 v32164, v29627
	move-wide/16 v21367, v5866
	move-object/16 v10842, v19856
	move-object/16 v21552, v9265
	move/16 v13326, v27101
	move-object/16 v30783, v15584
	move-wide/16 v31723, v18138
	move-object/16 v14626, v9001
	move-object/16 v2407, v30227
	move-wide/from16 v56, v1415
	move/16 v20584, v1811
	move-object/16 v9106, v3735
	move-wide/16 v15998, v3430
	move/16 v8937, v9027
	move-wide/16 v20270, v27952
	move-object/16 v24054, v3890
	move-wide/16 v23545, v4036
	move-object/16 v5583, v6879
	move-wide/16 v7838, v21736
	move/16 v12759, v25282
	move/16 v19876, v22611
	move-wide/16 v14013, v28187
	move/16 v4258, v17798
	move-object/16 v15912, v23883
	move-object/16 v4036, v20153
	move/16 v4369, v15787
	move-wide/16 v8526, v19917
	move/16 v30250, v23713
	move-wide/16 v12801, v15451
	move/16 v25282, v3532
	move/16 v52, v26003
	move/16 v3138, v18587
	move/16 v13099, v22574
	move/16 v15125, v9582
	move-object/16 v32048, v18036
	move/16 v19026, v18587
	move/16 v7974, v15670
	move-wide/16 v25073, v7177
	move/16 v24031, v2182
	move/16 v29762, v2900
	move-wide/16 v5114, v7022
	move-wide/16 v16291, v6087
	move/16 v24483, v11879
	move-wide/16 v3643, v1109
	move-wide/16 v2695, v31885
	move-wide/16 v4132, v382
	move-wide/16 v24939, v22688
	move-object/16 v24291, v852
	move/16 v5593, v4487
	move/16 v29279, v23558
	move-wide/16 v1950, v29324
	move/16 v26350, v30576
	move/16 v3946, v15761
	move/16 v11141, v12745
	move-object/16 v6105, v19064
	move/16 v19405, v1029
	move/16 v3444, v10732
	move/16 v28734, v16891
	move-object/16 v24503, v28548
	move/from16 v33, v18168
	move-wide/16 v31910, v12826
	move/16 v1847, v28449
	move-wide/16 v28871, v6326
	move-object/16 v24195, v29131
	move-object/16 v31475, v31463
	move/16 v8045, v9104
	move/16 v5588, v26704
	move-wide/16 v0, v23600
	move/16 v4031, v23678
	move-object/16 v17802, v21464
	move-object/16 v11006, v12506
	move/16 v25686, v3532
	move/16 v28971, v15476
	move/16 v15903, v31691
	move-wide/16 v19411, v21580
	move-wide/16 v26899, v2811
	move-object/16 v18617, v8685
	move-wide/16 v27807, v23600
	move/16 v24703, v23472
	move-object/16 v7898, v5181
	move/16 v5261, v28457
	move-object/16 v27026, v523
	move-wide/16 v7628, v2711
	move/16 v20181, v10012
	move-wide/16 v27066, v22688
	move-wide/16 v24842, v17132
	move-wide/16 v8475, v20420
	move/16 v9685, v19998
	move-wide/16 v23495, v28609
	move-wide/16 v18145, v6179
	move-wide/16 v13728, v15446
	move/16 v30466, v8057
	move/16 v8642, v6300
	move/16 v21440, v28971
	move/16 v1342, v19639
	move-object/from16 v158, v24925
	move/16 v32375, v4906
	move-wide/16 v31441, v16340
	move-object/16 v19419, v852
	move-wide/16 v32155, v24669
	move-wide/16 v9385, v10525
	move-wide/16 v6852, v26273
	move-wide/16 v4943, v3064
	move/16 v19884, v15659
	move/16 v29209, v20158
	move-wide/16 v22299, v2993
	move/16 v28769, v14519
	move/16 v29244, v22078
	move/16 v32186, v208
	move-wide/16 v11775, v28642
	move-wide/16 v5706, v31439
	move/16 v4037, v6661
	move-wide/16 v15346, v24407
	move/16 v18158, v1141
	move/16 v11141, v28401
	move-wide/16 v29725, v3643
	move-wide/16 v30772, v27807
	move/16 v27092, v10698
	move-wide/16 v32377, v9197
	move/16 v26050, v12596
	move-object/16 v27378, v6489
	move-object/16 v6248, v12274
	move/16 v28049, v22445
	move-wide/16 v19044, v13029
	move-wide/16 v31815, v25696
	move/16 v16461, v24380
	move-wide/16 v20253, v7990
	move-wide/16 v4573, v24846
	move-wide/16 v10486, v8353
	move/16 v30300, v31336
	move/16 v2744, v5650
	move-wide/16 v5042, v10151
	move-wide/16 v9132, v28187
	move-wide/16 v8256, v12689
	move/16 v9213, v2009
	move/16 v12670, v13808
	move-wide/16 v19904, v1716
	move/16 v3643, v29684
	move/16 v25499, v28469
	move-object/16 v11103, v6049
	move-object/16 v18722, v18641
	move/16 v17839, v6714
	move/16 v21138, v29172
	move-wide/16 v8186, v2278
	move-wide/16 v27635, v28590
	move/16 v4847, v18226
	move-wide/16 v19366, v14001
	move/16 v31807, v9336
	move-object/16 v31191, v16651
	move-wide/16 v1877, v24955
	move-object/16 v24380, v15584
	move-wide/16 v11746, v28960
	move-wide/16 v5559, v31660
	move/16 v4208, v7356
	move/16 v1713, v25007
	move/16 v5259, v22731
	move/16 v27479, v12910
	move-object/16 v21491, v23265
	move/16 v20547, v15375
	move-wide/16 v14421, v22552
	move/16 v30694, v11933
	move-wide/16 v15751, v32117
	move/16 v17762, v4369
	move-object/16 v27742, v9249
	move-object/16 v4541, v31337
	move/16 v4993, v26259
	move-wide/16 v24247, v1621
	move/16 v4909, v10737
	move/16 v22523, v32028
	move-object/16 v13091, v20838
	move-wide/16 v12969, v20931
	move/16 v4029, v15179
	move/16 v15849, v18348
	move-wide/16 v29464, v22552
	move-wide/16 v20308, v28590
	move-wide/16 v7304, v7970
	move/16 v32559, v8699
	move/16 v26879, v1735
	move-wide/16 v26923, v16639
	move-wide/16 v23552, v6498
	move-wide/16 v16788, v14891
	move-wide/16 v19064, v56
	move-object/16 v19652, v17215
	move/16 v432, v29961
	move-wide/16 v3820, v23968
	move/16 v13177, v32428
	move/16 v29541, v5467
	move-wide/16 v28122, v31439
	move-wide/16 v20657, v29937
	move-wide/16 v10714, v8483
	move-wide/16 v26564, v12824
	move-wide/16 v19319, v27545
	move/16 v2809, v27471
	move-wide/16 v12478, v3303
	move-object/16 v21868, v11103
	move-wide/16 v10924, v11079
	move/16 v5433, v5261
	move/16 v2873, v14650
	move-wide/16 v19891, v7205
	move-wide/16 v3019, v17896
	move/16 v208, v25063
	move/16 v28073, v20158
	move-wide/16 v28640, v5248
	move-wide/16 v27917, v16192
	move-wide/16 v23309, v1084
	move/16 v22526, v11517
	move/16 v13892, v31872
	move-object/16 v9552, v7794
	move-object/16 v27952, v8872
	move/16 v8602, v3444
	move/16 v22662, v4839
	move-wide/16 v19370, v7143
	move/from16 v2, v18928
	move-object/16 v12184, v21577
	move/16 v26508, v32193
	move-object/16 v24018, v18630
	move/16 v7483, v6577
	move/16 v27735, v27869
	move/16 v25117, v2009
	move-wide/16 v15981, v14391
	move/16 v14763, v9033
	move-wide/16 v28442, v20123
	move-wide/16 v17107, v11355
	move/16 v14871, v18418
	move/16 v16170, v21258
	move/16 v24232, v19126
	move/16 v13980, v4290
	move/16 v24714, v20860
	move-wide/16 v26270, v14339
	move/16 v5391, v16751
	move-wide/16 v23686, v20253
	move-wide/16 v26279, v25340
	move-object/16 v21681, v27983
	move-object/16 v17911, v10032
	move/16 v23052, v11166
	move/16 v19891, v21182
	move-wide/16 v29433, v13267
	move/16 v7187, v8214
	move/16 v7825, v8817
	move-wide/16 v27211, v8224
	move/16 v14761, v12557
	move/16 v14113, v3684
	move-wide/16 v20696, v21580
	move-wide/16 v23592, v31723
	move-wide/16 v18734, v6852
	move-object/16 v2172, v7319
	move-object/16 v15451, v19613
	move/16 v8200, v17943
	move-object/16 v11744, v16169
	move/16 v25537, v11198
	move-object/16 v10716, v10110
	move/16 v3856, v4001
	move/16 v25914, v31696
	move/16 v32604, v26829
	move/16 v1285, v9714
	move-wide/16 v3579, v31004
	move-wide/16 v24345, v22688
	move/16 v2010, v15787
	move-object/16 v22197, v27277
	move-wide/16 v13224, v30714
	move-object/16 v23277, v899
	move-wide/16 v10074, v7990
	move/16 v26966, v17029
	move/16 v17538, v9353
	move/16 v6805, v15523
	move-wide/16 v7257, v1605
	move-object/16 v8587, v5174
	move-wide/16 v10139, v11521
	move/16 v30484, v19750
	move/16 v26686, v14113
	move/16 v9289, v28060
	move-object/16 v17762, v24787
	move/16 v9064, v25008
	move-wide/16 v23144, v1105
	move/16 v10260, v22078
	move/16 v31955, v3679
	move/16 v3881, v19365
	move/16 v14296, v25367
	move-wide/16 v10260, v27635
	move/16 v31286, v6218
	move-object/16 v8054, v11384
	move/16 v9322, v28597
	move-wide/16 v20868, v7628
	move/16 v1716, v24824
	move/16 v19006, v28449
	move-wide/16 v16769, v12395
	move-wide/16 v19499, v20931
	move/16 v16472, v12383
	move/16 v15489, v12670
	move/16 v16688, v2896
	move-object/16 v14652, v30105
	move-wide/16 v8876, v12855
	move-wide/16 v19014, v29780
	move-wide/16 v6028, v27422
	move/16 v7105, v501
	move/16 v138, v32375
	move/16 v25838, v4906
	move/16 v3472, v14062
	move/16 v634, v20482
	move/16 v20808, v23082
	move/16 v26411, v13326
	move/16 v15805, v10698
	move-wide/16 v7021, v20657
	move-wide/16 v22838, v24950
	move/16 v24922, v10732
	move-wide/16 v25808, v16366
	move-object/16 v12313, v14262
	move/16 v1909, v32428
	move-object/16 v18273, v15298
	move-object/16 v2150, v28825
	move-wide/16 v7385, v5756
	move/16 v25889, v27479
	move-wide/16 v9651, v16026
	move/16 v17273, v23754
	move/16 v23707, v11141
	move/16 v27146, v27101
	move/16 v20634, v7434
	move-wide/16 v5250, v24669
	move-object/16 v23688, v12230
	move-wide/16 v9751, v24247
	move-wide/16 v19201, v22838
	move-wide/16 v27584, v16380
	move-wide/16 v25936, v8876
	move-object/16 v22846, v31337
	move-object/16 v29464, v24643
	move/16 v14466, v19296
	move-wide/16 v27584, v1973
	move/16 v32590, v24726
	move-object/16 v7281, v31954
	move-wide/16 v19639, v18972
	move/16 v2172, v6805
	move-wide/16 v2930, v31439
	move/16 v6555, v8777
	move/16 v13601, v4369
	move/16 v21563, v4906
	move-wide/16 v16622, v10370
	move/16 v3720, v22136
	move-wide/16 v10421, v14853
	move-wide/16 v25632, v16901
	move/16 v27356, v31597
	move-object/16 v18659, v15122
	move/16 v8497, v13569
	move-wide/16 v20067, v23495
	move-wide/16 v21681, v7440
	move-object/16 v11458, v4851
	move/16 v8877, v4029
	move/16 v28298, v27228
	move/16 v4689, v10265
	move-object/16 v30674, v19429
	move-wide/16 v29937, v7818
	move-wide/16 v32377, v19161
	move-object/16 v19006, v26516
	move/16 v30503, v20863
	move-object/16 v3099, v6489
	move-wide/16 v8038, v2674
	move-object/16 v8339, v12055
	move/16 v17455, v11269
	move/16 v19139, v19559
	move/16 v16762, v24916
	move-object/16 v523, v18722
	move-object/16 v3917, v3735
	move/16 v11242, v617
	move/16 v1451, v23109
	move-object/16 v28590, v13091
	move/16 v20622, v24714
	move-wide/16 v25696, v7914
	move/16 v18383, v6905
	move/16 v1556, v4906
	move-wide/16 v15544, v2104
	move-wide/16 v213, v15925
	move-wide/16 v23105, v31869
	move/16 v13717, v19312
	move/16 v17211, v7450
	move/16 v792, v25118
	move/16 v14517, v28049
	move-wide/16 v7443, v26127
	move/16 v24710, v19139
	move-object/16 v5433, v12222
	move-object/16 v16335, v21491
	move/16 v7153, v23109
	move/16 v928, v25957
	move-wide/16 v8388, v14582
	move-object/16 v17325, v8961
	move-wide/16 v3820, v7122
	move/16 v7935, v9582
	move/16 v28401, v3413
	move/16 v16793, v12028
	move/16 v8138, v24296
	move/16 v19830, v10265
	move/16 v29186, v10353
	move/16 v3321, v4815
	move/16 v31742, v21981
	move-wide/16 v24514, v23962
	move/16 v276, v15179
	move/16 v7974, v13340
	move-object/16 v9623, v21935
	move-wide/16 v19060, v14957
	move/16 v21822, v15612
	move-object/16 v10842, v30783
	move/16 v5181, v2976
	move-object/16 v6714, v23277
	move-object/16 v13593, v30057
	move-wide/16 v18311, v31419
	move/16 v15834, v7372
	move/16 v24611, v10265
	move/16 v9735, v8918
	move-wide/16 v29530, v8256
	move/16 v22958, v14876
	move-wide/16 v30846, v28720
	move/16 v13380, v7434
	move/16 v6654, v21106
	move/16 v23548, v7058
	move/16 v30666, v22872
	move/16 v8306, v31955
	move/16 v391, v10012
	move-wide/from16 v162, v15617
	move/16 v19958, v30694
	move-wide/16 v2132, v25808
	move/16 v9865, v19699
	move/16 v25436, v10580
	move/16 v7238, v9353
	move/16 v8167, v22293
	move/16 v29968, v30446
	move/16 v10045, v14296
	move/16 v7534, v20170
	move/16 v23660, v29649
	move-object/16 v15235, v18036
	move/16 v23043, v2009
	move/16 v10611, v1713
	move-wide/16 v17383, v12801
	move-wide/16 v19496, v6374
	move/16 v2852, v24383
	move/16 v7045, v20170
	move-wide/16 v14993, v25073
	move-object/16 v4935, v6961
	move-wide/16 v9261, v4561
	move-wide/16 v19417, v28640
	move-wide/16 v10743, v20985
	move/16 v14891, v22872
	move-wide/16 v24922, v19585
	move/16 v8788, v6555
	move-wide/16 v20992, v6669
	move/16 v27655, v6896
	move-wide/16 v17510, v29530
	move/16 v32558, v28457
	move-wide/16 v25814, v22785
	move-object/16 v12921, v31499
	move/16 v21821, v29526
	move-wide/16 v23754, v18170
	move-object/16 v8694, v21848
	move/16 v6738, v32158
	move/16 v8209, v31566
	move/16 v31408, v19899
	move/16 v26893, v14761
	move-object/16 v20525, v8289
	move/16 v30652, v23511
	move/16 v26686, v7118
	move-wide/16 v10157, v2001
	move-wide/16 v25831, v19914
	move-wide/16 v17593, v3940
	move-wide/16 v16299, v3430
	move-wide/16 v22526, v25073
	move/16 v10154, v21893
	move-wide/16 v31875, v9651
	move/16 v10403, v3086
	move-wide/16 v20314, v19370
	move-object/16 v15469, v18617
	move-wide/16 v10564, v18342
	move-wide/16 v15053, v32769
	move/16 v6768, v3881
	move/16 v691, v29187
	move/16 v24675, v8497
	move/16 v21534, v20158
	move-wide/16 v21984, v26590
	move-wide/16 v19643, v28260
	move/16 v16654, v29186
	move-object/16 v9010, v8818
	move-wide/16 v1938, v26564
	move-wide/16 v1284, v10645
	move/16 v7990, v30652
	move/16 v3946, v20622
	move-wide/16 v9164, v29780
	move/16 v16100, v7058
	move-object/16 v1909, v11384
	move/16 v16748, v8329
	move/16 v17396, v8216
	move-wide/16 v20432, v8149
	move-wide/16 v32239, v872
	move/16 v20714, v30874
	move-wide/16 v14855, v21702
	move-object/16 v16937, v22764
	move/16 v16278, v3413
	move/16 v12698, v19858
	move/16 v15346, v10380
	move/16 v2894, v7744
	move/16 v4402, v28971
	move-wide/16 v2883, v3296
	move/16 v24166, v6814
	move-wide/16 v6517, v4943
	move-object/16 v26556, v11928
	move/16 v7517, v9735
	move-wide/16 v16167, v19496
	move-wide/16 v3490, v23144
	move/16 v3664, v27717
	move-object/16 v21866, v27952
	move-wide/16 v9010, v14659
	move/16 v9557, v25436
	move/16 v20069, v3472
	move-wide/16 v2811, v29004
	move/16 v1382, v14519
	move-wide/16 v17562, v19417
	move-object/16 v24977, v7977
	move/16 v30727, v18802
	move/16 v17201, v5650
	move/16 v25994, v14062
	move-wide/16 v4019, v20420
	move/16 v20069, v4839
	move-wide/16 v21904, v8186
	move/16 v3706, v18033
	move/16 v25285, v13099
	move/16 v15307, v24273
	move-object/16 v13487, v31618
	move-wide/16 v26096, v2674
	move/16 v17924, v25828
	move/16 v2182, v10012
	move/16 v4784, v12518
	move/16 v2593, v11198
	move-wide/16 v27138, v22838
	move-object/16 v11674, v30639
	move-wide/16 v4062, v20792
	move-object/16 v5140, v11875
	move-object/16 v29433, v11744
	move-wide/16 v20686, v25632
	move/16 v26928, v9685
	move-wide/16 v580, v17348
	move/16 v29689, v2479
	move-object/16 v3562, v852
	move-wide/16 v31155, v1732
	move-wide/16 v9907, v21494
	move/16 v3227, v5588
	move/16 v17659, v16649
	move-wide/16 v5181, v19044
	move/16 v31700, v19974
	move-wide/16 v13029, v32534
	move-object/16 v13266, v16430
	move-object/16 v30645, v29464
	move-object/16 v27545, v1222
	move/16 v4632, v23562
	move-wide/16 v7637, v6081
	move-wide/16 v26704, v16192
	move/16 v1287, v21563
	move-wide/16 v32061, v2695
	move/16 v28636, v8937
	move/16 v1157, v15761
	move/16 v20263, v17839
	move-wide/16 v13726, v10743
	move/16 v4804, v1382
	move-wide/16 v30471, v17780
	move/16 v31679, v10403
	move-wide/16 v11597, v26472
	move/16 v21106, v20263
	move-wide/16 v7205, v1877
	move/16 v17679, v8937
	move-object/16 v23312, v6065
	move/16 v16788, v138
	move/16 v29598, v29627
	move/16 v25482, v1769
	move/16 v9060, v23651
	move/16 v27405, v24905
	move/16 v8633, v3856
	move-object/16 v6295, v18417
	move-object/16 v18411, v21464
	move/16 v24422, v138
	move/16 v25651, v8642
	move/16 v26879, v2976
	move/16 v32208, v31034
	move/16 v6973, v17839
	move/16 v28974, v27903
	move/16 v19964, v15685
	move/16 v28911, v12918
	move-object/16 v14005, v12611
	move-wide/16 v26499, v28720
	move-wide/16 v2905, v3418
	move/16 v12038, v6979
	move-wide/16 v10961, v1877
	move/16 v11211, v25828
	move/16 v18472, v20622
	move-object/16 v16748, v22773
	move/16 v26546, v11662
	move-object/16 v304, v15346
	move-wide/16 v1047, v4573
	move-wide/16 v16102, v15201
	move/16 v4784, v5374
	move/16 v29684, v21538
	move-wide/16 v304, v19585
	move/16 v23862, v14026
	move/16 v26326, v16933
	move/16 v117, v13717
	move-object/16 v17510, v15378
	move-wide/16 v7858, v23213
	move-wide/16 v1715, v28317
	move/16 v19750, v10580
	move/16 v12966, v2896
	move-wide/16 v7285, v22315
	move/16 v12614, v8280
	move-wide/16 v11741, v10952
	move/16 v29536, v26093
	move/16 v8694, v14026
	move/16 v32650, v12557
	move/16 v273, v22082
	move/16 v24333, v24432
	move/16 v32164, v26350
	move-object/16 v16167, v15451
	move/16 v20997, v22662
	move/16 v30652, v3946
	move/16 v18388, v8264
	move/16 v29559, v28049
	move-wide/16 v16100, v14024
	move-wide/16 v30256, v4573
	move/16 v20848, v29952
	move/16 v5246, v1451
	move-object/16 v21310, v21552
	move-object/16 v16859, v888
	move-wide/16 v25354, v16942
	move/16 v28201, v21538
	move/16 v24589, v6979
	move/16 v15298, v20714
	move-object/16 v16352, v12274
	move-wide/16 v8038, v8822
	move-object/16 v152, v7794
	move/16 v2289, v1481
	move/16 v20158, v24422
	move/16 v30898, v7356
	move-object/16 v16366, v7977
	move/16 v16585, v29059
	move/16 v7483, v25063
	move-object/16 v16386, v5403
	move/16 v7673, v12482
	move-object/16 v7722, v21868
	move/16 v29511, v10041
	move/16 v24345, v17505
	move/16 v21968, v4804
	move/16 v23270, v21677
	move/16 v12539, v1847
	move-object/16 v16021, v1909
	move/16 v16871, v30759
	move-object/16 v25441, v29088
	move/16 v3869, v32559
	move/16 v20686, v17273
	move-wide/16 v28648, v3274
	move/16 v4429, v8045
	move/16 v10517, v23160
	move/16 v4307, v14761
	move-wide/16 v30965, v3418
	move-wide/16 v31035, v29823
	move/16 v8138, v23558
	move/16 v8832, v5473
	move/16 v11878, v5650
	move-object/16 v8858, v17802
	move-wide/16 v12760, v22517
	move-object/from16 v58, v24018
	move-wide/16 v18490, v29284
	move/16 v9865, v18462
	move-wide/16 v13707, v12458
	move-object/16 v20547, v152
	move/16 v28285, v19750
	move/16 v31233, v11242
	move-object/16 v7772, v32253
	move-wide/16 v26846, v20696
	move/16 v15684, v24166
	move-object/16 v26422, v30765
	move/16 v18014, v15787
	move/16 v28075, v23975
	move/16 v13795, v12670
	move/16 v32256, v22168
	move-wide/16 v8371, v31553
	move-object/16 v29563, v6879
	move-wide/16 v25887, v4062
	move/16 v13282, v26480
	move/16 v14750, v21342
	move-wide/16 v22204, v22422
	move/16 v16654, v15391
	move-wide/16 v31029, v28982
	move-wide/16 v9831, v16380
	move-object/16 v7797, v20794
	move-object/16 v18138, v28590
	move-object/16 v11601, v8685
	move-object/16 v21426, v31202
	move-object/16 v19141, v8329
	move-object/16 v6967, v9106
	move-wide/16 v7356, v26472
	move-wide/16 v2913, v7626
	move/16 v2278, v8777
	move/16 v32183, v27458
	move-object/16 v26796, v8054
	move-object/16 v13091, v12461
	move-object/16 v32391, v8872
	move-object/16 v9735, v27464
	move-wide/16 v16932, v23686
	move-object/16 v7532, v10842
	move-wide/16 v4453, v1971
	move-object/16 v26035, v26796
	move-wide/16 v2873, v0
	move/16 v18511, v28449
	move-object/16 v14834, v4338
	move/16 v32590, v4487
	move-object/16 v4423, v27983
	move-wide/16 v3490, v23105
	move/16 v30664, v14177
	move/16 v11355, v26893
	move-object/16 v12761, v23883
	move/16 v31062, v24100
	move/16 v32045, v31034
	move/16 v3138, v25924
	move-wide/16 v28911, v1938
	move-wide/16 v25731, v2104
	move-wide/16 v23091, v6028
	move/16 v7786, v20894
	move-wide/16 v11710, v10564
	move-wide/16 v29765, v23686
	move/16 v14240, v10012
	move-wide/16 v7303, v3296
	move/16 v15617, v31700
	move/16 v28085, v21819
	move/16 v173, v8774
	move/16 v4790, v11636
	move-wide/16 v20782, v21344
	move-object/16 v10210, v6049
	move/16 v10294, v11332
	move-wide/16 v16120, v31815
	move/16 v31275, v9714
	move-object/16 v11960, v23688
	move-object/16 v7450, v6967
	move/16 v13888, v14891
	move/16 v6208, v2515
	move/16 v1825, v18417
	move/16 v9334, v32238
	move-object/16 v2953, v30105
	move/16 v2031, v26893
	move-object/16 v7908, v32728
	move/16 v6973, v23511
	move-wide/16 v23309, v4327
	move-object/16 v13441, v6714
	move-wide/16 v4150, v2777
	move-wide/16 v16170, v13279
	move/16 v9375, v28073
	move/16 v17774, v28734
	move/16 v6719, v18388
	move/16 v10525, v23688
	move-wide/16 v1955, v2711
	move/16 v21583, v7372
	move-wide/16 v7238, v25887
	move-wide/16 v3586, v20432
	move-wide/16 v3490, v14949
	move-wide/16 v29464, v21989
	move-wide/16 v13857, v26704
	move-wide/16 v19069, v19060
	move/16 v7156, v9865
	move/16 v747, v19830
	move-wide/16 v20153, v17107
	move-wide/16 v18077, v6347
	move-wide/16 v2964, v3064
	move-wide/16 v27584, v28642
	move/16 v5212, v7898
	move-wide/16 v16751, v2001
	move/16 v3881, v31597
	move/16 v20386, v32028
	move/16 v25880, v11445
	move/16 v11684, v3559
	move/16 v18488, v2
	move/16 v10621, v15805
	move-wide/16 v17399, v32572
	move/16 v13064, v23618
	move/16 v31032, v24611
	move-object/16 v30231, v16021
	move-object/16 v10337, v28075
	move/16 v19064, v10380
	move-object/16 v6850, v24977
	move/16 v15893, v2220
	move/16 v795, v6905
	move/16 v23781, v4290
	move-wide/16 v10249, v20308
	move-wide/16 v12592, v19193
	move/from16 v223, v1141
	move/16 v6590, v16552
	move/16 v24788, v6805
	move-wide/16 v3974, v30752
	move/16 v25323, v9375
	move/16 v26270, v26024
	move/16 v7653, v27654
	move/16 v24832, v29968
	move/16 v11875, v25537
	move/16 v4855, v29803
	move-wide/16 v12285, v28767
	move-wide/16 v7646, v32632
	move-wide/16 v29400, v27907
	move/16 v23009, v13601
	move-wide/16 v27471, v597
	move-wide/16 v5528, v24372
	move-wide/16 v9601, v21904
	move/16 v22238, v3875
	move-wide/16 v15880, v176
	move-object/16 v28547, v6489
	move/16 v8320, v9353
	move-wide/16 v12147, v24939
	move/16 v21289, v5629
	move-wide/16 v31467, v18999
	move-wide/16 v29107, v3418
	move-object/16 v24077, v158
	move/16 v5120, v14891
	move/16 v6752, v5120
	move/16 v1108, v18118
	move/16 v25008, v14062
	move/16 v26474, v8817
	move-wide/16 v25076, v6852
	move/16 v4001, v26003
	move/16 v24514, v12343
	move/16 v20691, v26270
	move-wide/16 v3308, v31564
	move-wide/16 v20596, v26846
	move/16 v22084, v1529
	move-wide/16 v24791, v10534
	move-object/16 v26024, v6654
	move/16 v15761, v22078
	move-object/16 v31358, v792
	move-wide/16 v26079, v25076
	move-wide/16 v17864, v476
	move-wide/16 v16038, v30026
	move-object/16 v20889, v12184
	move-wide/16 v8118, v10249
	move/16 v20153, v13702
	move-object/16 v27286, v4661
	move-wide/16 v1247, v4453
	move/16 v17985, v17455
	move/16 v3141, v21306
	move/16 v14880, v32093
	move-wide/16 v25731, v25104
	move-wide/16 v11578, v5866
	move-wide/16 v1067, v18972
	move-object/16 v29288, v9249
	move/16 v6836, v19136
	move-wide/16 v13282, v15568
	move/16 v293, v25857
	move/16 v15574, v6300
	move/16 v15736, v14055
	move-wide/16 v32239, v7628
	move-wide/16 v16794, v19366
	move-object/16 v6223, v18617
	move-wide/16 v8649, v30069
	move/16 v26436, v11198
	move-wide/16 v12762, v18311
	move/16 v16277, v26556
	move/16 v12855, v28457
	move/16 v2295, v3321
	move-object/16 v16894, v21491
	move-object/16 v28974, v4524
	move-wide/16 v24892, v6974
	move-wide/16 v11438, v1950
	move/16 v31982, v7653
	move/16 v6515, v23559
	move/16 v32772, v31034
	move-wide/16 v3330, v9601
	move-object/16 v10249, v6654
	move/16 v30152, v2900
	move-wide/16 v28424, v21989
	move-object/16 v5137, v18564
	move-object/from16 v208, v5635
	move/16 v23388, v10551
	move-object/16 v23562, v32604
	move-object/16 v19613, v899
	move-wide/16 v19370, v5354
	move/16 v3661, v11782
	move-wide/16 v27242, v27892
	move/16 v9531, v26411
	move/16 v26893, v3884
	move-wide/16 v1298, v2104
	move-wide/16 v24966, v2777
	move/16 v6958, v17798
	move-object/16 v21342, v32391
	move/16 v5354, v21534
	move/16 v3099, v19102
	move-wide/16 v229, v8388
	move-wide/16 v4925, v2071
	move-wide/16 v14013, v24091
	move/16 v14200, v24664
	move/16 v19129, v16891
	move/16 v9218, v24916
	move/16 v9167, v24802
	move-wide/16 v32749, v213
	move/16 v8511, v23578
	move/16 v14177, v8214
	move-object/16 v5732, v30611
	move-object/16 v6854, v30227
	move/16 v4819, v7499
	move-wide/16 v25924, v27331
	move/16 v16793, v31691
	move/16 v22130, v18388
	move/16 v5496, v16277
	move-wide/16 v21681, v8038
	move/16 v22731, v8694
	move-wide/16 v12810, v2262
	move-wide/16 v13612, v10260
	move-object/16 v8961, v14005
	move/16 v31636, v29689
	move-object/16 v15981, v16651
	move-wide/16 v5374, v20822
	move/16 v21446, v6442
	move/16 v10464, v13289
	move/16 v19734, v10380
	move/16 v9104, v8167
	move/16 v21666, v8280
	move/16 v24075, v17911
	move/16 v16299, v23830
	move/16 v31488, v14040
	move-wide/16 v29575, v20931
	move-wide/16 v30298, v27211
	move/16 v24926, v18968
	move-wide/16 v9032, v16932
	move/16 v26536, v19226
	move/16 v29071, v9384
	move/16 v2408, v21369
	move/16 v23494, v24718
	move-wide/16 v6555, v12762
	move-object/16 v13579, v516
	move/16 v8388, v10894
	move-wide/16 v13165, v5042
	move-object/16 v5114, v15912
	move-wide/16 v15736, v14579
	move/16 v31742, v273
	move/16 v7427, v27344
	move/16 v812, v30874
	move/16 v4402, v8777
	move-wide/16 v18041, v30471
	move/16 v617, v26966
	move/16 v8825, v31358
	move/16 v9261, v15179
	move-wide/16 v25808, v1938
	move/16 v11636, v27356
	move/16 v24772, v9065
	move-wide/16 v52, v7356
	move/16 v1127, v19365
	move/16 v2136, v5246
	move/16 v18486, v29146
	move-wide/16 v2220, v14562
	move/16 v3707, v23160
	move/16 v21536, v19884
	move-object/16 v23559, v21848
	move/16 v15925, v19064
	move/16 v10527, v9322
	move/16 v28723, v9027
	move/16 v9098, v28070
	move-object/16 v18630, v11674
	move/16 v19679, v3141
	move/16 v4197, v5403
	move-wide/16 v29589, v19690
	move/16 v6873, v30666
	move/16 v5986, v812
	move-object/16 v26409, v20889
	move-wide/16 v30186, v8516
	move-wide/16 v13113, v9132
	move-object/16 v9751, v6039
	move/16 v8329, v29615
	move/16 v7252, v13888
	move-wide/16 v25633, v6179
	move-wide/16 v29952, v24193
	move/16 v3078, v26879
	move-wide/16 v2220, v25010
	move-wide/16 v27212, v15443
	move/16 v11741, v28713
	move/16 v5331, v19559
	move/16 v24669, v11636
	move-wide/16 v31233, v5042
	move/16 v11770, v10165
	move-object/16 v30611, v19419
	move/16 v4327, v10265
	move/16 v1396, v31982
	move-wide/from16 v121, v8483
	move/16 v11671, v12383
	move-wide/16 v27903, v6581
	move/16 v18033, v7974
	move/16 v28675, v29736
	move-wide/16 v15593, v4319
	move/16 v31807, v4369
	move-object/16 v22720, v14880
	move/16 v3227, v28449
	move-wide/16 v391, v6326
	move-wide/16 v3472, v27242
	move-object/16 v30300, v14401
	move/16 v3086, v30270
	move/16 v4462, v26050
	move/16 v30200, v16688
	move-wide/16 v13857, v18734
	move-wide/16 v13796, v774
	move/16 v29209, v9060
	move/16 v17667, v18419
	move-wide/16 v27260, v26273
	move/16 v3138, v30525
	move/16 v15085, v7754
	move/16 v4429, v4194
	move-object/16 v7451, v27378
	move/16 v25323, v12252
	move-object/16 v8054, v9623
	move-object/16 v15530, v7797
	move-object/16 v22598, v28590
	move-wide/16 v501, v18041
	move/16 v27795, v9104
	move/16 v14132, v9531
	move-object/16 v11770, v5981
	move-wide/16 v9194, v16794
	move-wide/16 v29368, v5042
	move-wide/16 v26418, v3725
	move/16 v17608, v15581
	move/16 v27513, v15685
	move/16 v2289, v22776
	move-wide/16 v7385, v12801
	move/16 v10110, v20202
	move-wide/16 v30069, v32769
	move/16 v3890, v4307
	move/16 v19847, v28469
	move/16 v31131, v28469
	move-object/16 v23760, v6961
	move-wide/16 v30325, v27697
	move/16 v12244, v9167
	move-object/16 v6049, v888
	move/16 v7601, v31636
	move-object/16 v12982, v10839
	move/16 v6049, v30484
	move/16 v32579, v13326
	move/16 v17211, v812
	move-wide/16 v15530, v17780
	move/16 v10421, v30200
	move-wide/16 v11628, v30471
	move-wide/16 v30547, v3418
	move-wide/16 v4507, v7440
	move/16 v32375, v10865
	move/16 v4586, v31408
	move/16 v5409, v15489
	move-wide/16 v26621, v30547
	move/16 v2479, v9064
	move/16 v16026, v23707
	move/16 v13613, v24664
	move/16 v8149, v18786
	move-object/16 v8251, v18642
	move-wide/16 v14582, v27471
	move-wide/16 v30282, v7062
	move-wide/16 v25263, v26704
	move-wide/16 v7990, v26233
	move/16 v23279, v5120
	move-wide/16 v17399, v30026
	move/16 v30765, v19048
	move-wide/16 v7641, v13029
	move-wide/16 v27787, v3579
	move-wide/16 v30535, v23968
	move/16 v14949, v24714
	move-object/16 v28873, v27640
	move-wide/16 v23073, v14855
	move-object/16 v29968, v12230
	move/16 v27252, v17528
	move-wide/16 v14643, v30471
	move-wide/16 v22517, v22526
	move/16 v10650, v19026
	move-wide/16 v4204, v13113
	move/16 v12918, v1025
	move-wide/16 v794, v30022
	move/16 v21882, v21538
	move-wide/16 v10732, v16932
	move-wide/16 v10468, v8371
	move/16 v6100, v4568
	move/16 v26925, v4197
	move/16 v8642, v29627
	move/16 v8371, v3413
	move-wide/16 v16942, v3472
	move-wide/16 v16100, v18041
	move-wide/16 v25104, v16794
	move-wide/16 v14880, v29823
	move-object/16 v16550, v8339
	move/16 v14747, v617
	move/16 v32086, v4255
	move/16 v5908, v6298
	move-wide/16 v9966, v20308
	move/16 v8225, v31034
	move/16 v14841, v11916
	move-object/16 v10331, v13263
	move-wide/16 v25819, v20985
	move/16 v12184, v32028
	move-wide/16 v30752, v22204
	move-wide/16 v8118, v176
	move/16 v4586, v11064
	move-wide/16 v1827, v25696
	move/16 v31240, v31408
	move/16 v22208, v6805
	move-wide/16 v3978, v6374
	move-wide/16 v21926, v12013
	move-wide/16 v27161, v29952
	move/16 v31700, v16553
	move-wide/16 v27795, v28317
	move/16 v17169, v27344
	move-wide/16 v31869, v32769
	move-wide/16 v26954, v19496
	move-wide/16 v29482, v476
	move-wide/16 v18014, v728
	move-object/16 v17506, v25470
	move-wide/16 v8280, v783
	move/16 v24345, v29054
	move-wide/16 v28974, v19060
	move/16 v25915, v487
	move-wide/16 v1054, v1688
	move/16 v31013, v21563
	move/16 v1381, v3917
	move/from16 v0, v15085
	move-wide/16 v3585, v16192
	move/16 v15469, v8633
	move/16 v31982, v8045
	move/16 v7963, v4037
	move-wide/16 v7045, v176
	move-wide/16 v4037, v27331
	move-object/16 v19861, v30290
	move/16 v352, v4018
	move/16 v6690, v10839
	move/16 v26798, v2031
	move/16 v25846, v11933
	move/16 v31748, v9104
	move-wide/16 v16200, v27917
	move/16 v23477, v17608
	move-wide/16 v27436, v16632
	move-wide/16 v7434, v2907
	move/16 v18946, v31278
	move/16 v8879, v2593
	move-wide/16 v10874, v17999
	move/16 v11211, v12302
	move/16 v2132, v4432
	move-wide/16 v15166, v6709
	move-wide/16 v20263, v56
	move/16 v21163, v15179
	move-wide/16 v13728, v4603
	move-wide/16 v3072, v7177
	move/16 v17659, v29598
	move/16 v32299, v9271
	move/16 v9720, v29276
	move/16 v19830, v17667
	move-wide/16 v30268, v10952
	move/16 v11597, v32774
	move-object/16 v26621, v23760
	move-wide/16 v3634, v3359
	move/16 v24925, v16762
	move-object/16 v12004, v32728
	move-object/16 v23494, v19262
	move/16 v150, v13865
	move/16 v1342, v10045
	move/16 v15346, v4369
	move-object/16 v14396, v5635
	move-wide/16 v3536, v16739
	move/16 v24344, v32208
	move-wide/16 v32444, v16877
	move-wide/16 v20274, v10732
	move-wide/16 v11243, v30965
	move/16 v13677, v22562
	move-wide/16 v22293, v25073
	move-wide/16 v28122, v6427
	move-wide/16 v2136, v2777
	move/16 v5698, v7499
	move/16 v923, v1222
	move-wide/16 v14466, v26715
	move/16 v6324, v12596
	move-wide/16 v18137, v14579
	move-wide/16 v6783, v28720
	move/16 v27713, v6896
	move/16 v15414, v21822
	move-wide/16 v30714, v16877
	move/16 v15066, v13717
	move/16 v2988, v31561
	move/16 v29559, v2
	move/16 v2623, v31597
	move/16 v28748, v20181
	move-wide/16 v30278, v13483
	move/16 v27146, v10700
	move/16 v16048, v24710
	move-wide/16 v32636, v12478
	move-object/16 v28457, v5403
	move/16 v13164, v5593
	move-wide/16 v432, v30790
	move-object/16 v27049, v19562
	move/16 v28881, v3157
	move-wide/16 v30783, v18342
	move-wide/16 v15378, v4736
	move/16 v17071, v15690
	move/16 v20863, v20158
	move/16 v31698, v8694
	move/16 v30278, v29704
	move-object/16 v19129, v8858
	move-wide/16 v17747, v23105
	move/16 v2785, v4001
	move-object/16 v13726, v32048
	move/16 v10962, v27735
	move-wide/16 v2073, v12810
	move/16 v7346, v28129
	move-wide/16 v17437, v6741
	move/16 v14952, v18511
	move-wide/16 v18929, v29464
	move-wide/16 v2407, v17593
	move-wide/16 v4487, v15378
	move/16 v32418, v5732
	move/16 v10116, v17924
	move/16 v11521, v31286
	move-wide/16 v10188, v7177
	move/16 v23680, v10865
	move-wide/16 v1878, v14609
	move-wide/16 v20420, v19639
	move-object/16 v30421, v22256
	move/16 v7680, v1382
	move/16 v7177, v4029
	move-wide/16 v18014, v16632
	move-wide/16 v21577, v14609
	move/16 v11803, v30694
	move-wide/16 v24643, v1411
	move-object/16 v29003, v6065
	move-wide/16 v28285, v25057
	move/16 v28317, v14841
	move/16 v15139, v18786
	move/16 v6439, v8602
	move/16 v158, v22082
	move-wide/16 v25645, v15568
	move/16 v18843, v21821
	move/16 v32308, v26563
	move/16 v18077, v5261
	move/16 v16568, v19989
	move/16 v18094, v19844
	move-wide/16 v5467, v27892
	move/16 v22168, v4889
	move/16 v21126, v5114
	move/16 v2913, v6905
	move-wide/16 v13749, v12801
	move/16 v30300, v24905
	move/16 v31869, v28386
	move-object/16 v16550, v8289
	move/16 v9514, v12142
	move-object/16 v5478, v28590
	move/16 v16947, v32275
	move-wide/16 v1579, v19417
	move-wide/16 v23153, v32572
	move/16 v14633, v5282
	move-object/16 v12699, v7898
	move-object/16 v2462, v58
	move-wide/16 v12412, v31439
	move/16 v14452, v27655
	move-wide/16 v14949, v15530
	move-wide/16 v23545, v31439
	move/16 v14643, v5908
	move/16 v31940, v14240
	move/16 v15357, v31275
	move-object/16 v25063, v8685
	move/16 v3472, v26631
	move-object/16 v26113, v18722
	move/16 v19978, v20863
	move-wide/16 v1950, v26923
	move/16 v9457, v24011
	move/16 v4487, v25914
	move-wide/16 v18172, v26105
	move-wide/16 v6218, v12395
	move/16 v13693, v2497
	move-object/16 v27277, v6675
	move/16 v19224, v6738
	move-wide/16 v30783, v25263
	move/16 v11980, v15960
	move-wide/16 v17802, v27352
	move-object/16 v7732, v11006
	move/16 v9751, v30270
	move/16 v32645, v23830
	move-wide/16 v24538, v24499
	move/16 v9422, v16157
	move/16 v3684, v20622
	move-object/16 v9066, v3548
	move/16 v26508, v20660
	move/16 v1465, v4432
	move/16 v26841, v19312
	move-wide/16 v31020, v31815
	move/16 v24128, v17608
	move-wide/16 v2529, v15272
	move/16 v26738, v7058
	move/16 v21418, v10331
	move/16 v18027, v19064
	move/16 v29024, v924
	move-wide/16 v3706, v26590
	move-wide/16 v4208, v501
	move-object/16 v32256, v10716
	move-wide/16 v2683, v8038
	move-wide/16 v12437, v1732
	move/16 v28572, v26161
	move/16 v5215, v10389
	move/16 v5737, v5212
	move/16 v7963, v14517
	move/16 v2722, v18511
	move-object/16 v19894, v18294
	move-object/16 v19060, v19429
	move-object/16 v3298, v19129
	move/16 v8647, v14761
	move-wide/16 v8649, v18137
	move/16 v24149, v9353
	move/16 v21821, v25499
	move/16 v22574, v24589
	move/16 v16026, v10116
	move/16 v8401, v28070
	move/16 v11793, v23558
	move-wide/16 v11565, v7434
	move/16 v12626, v1735
	move/16 v5737, v26050
	move-object/16 v2976, v32048
	move/16 v785, v6406
	move-object/16 v28471, v5174
	move/16 v16401, v32559
	move-wide/16 v16291, v21119
	move-wide/16 v9318, v16291
	move/16 v14871, v10389
	move-object/16 v32768, v792
	move/16 v17278, v2147
	move/16 v2800, v10700
	move/16 v31334, v7797
	move/16 v669, v26857
	move-wide/16 v19699, v22738
	move/16 v23618, v2515
	move/16 v32048, v23707
	move/16 v15876, v9098
	move/16 v1490, v5290
	move-object/16 v22954, v22828
	move/16 v19830, v271
	move-wide/16 v8375, v18041
	move-wide/16 v559, v728
	move-wide/16 v3532, v31660
	move/16 v31739, v27479
	move-wide/16 v339, v2695
	move/16 v23043, v19830
	move/16 v9250, v11662
	move-wide/16 v29057, v9010
	move/16 v1073, v8832
	move-wide/16 v29389, v21702
	move-wide/16 v5575, v14065
	move/16 v21406, v24149
	move/16 v26422, v2247
	move/16 v14505, v23698
	move-wide/16 v15161, v19585
	move/16 v20058, v14517
	move-wide/16 v13099, v23091
	move-wide/16 v16852, v3490
	move/16 v6075, v17839
	move/16 v31566, v15298
	move-object/16 v20067, v20153
	move-wide/16 v10221, v27584
	move/16 v20243, v17071
	move-wide/16 v3444, v25572
	move-wide/16 v19164, v23091
	move-wide/16 v17455, v671
	move-wide/16 v23441, v27917
	move/16 v29619, v18077
	move-object/16 v4540, v10842
	move/16 v13029, v19541
	move-wide/16 v14919, v19366
	move-wide/16 v18000, v2195
	move-object/16 v32186, v24296
	move-wide/16 v18436, v3840
	move-wide/16 v5840, v16639
	move-object/16 v9384, v15584
	move-object/16 v17723, v10525
	move-object/16 v31233, v13015
	move/16 v18226, v22505
	move-object/16 v27117, v3298
	move-wide/16 v30517, v31419
	move-object/16 v18253, v2620
	move/16 v5629, v31636
	move-wide/16 v24031, v30981
	move-object/16 v24695, v21135
	move/16 v24128, v20863
	move/16 v23268, v29736
	move/16 v5336, v276
	move-object/16 v1298, v23883
	move/16 v11840, v11671
	move/16 v26795, v23883
	move-wide/16 v23686, v15255
	move-wide/16 v10716, v20782
	move/16 v12717, v16278
	move/16 v26893, v25957
	move/16 v29004, v3917
	move-wide/16 v15745, v25263
	move-object/16 v25117, v13726
	move-wide/16 v2228, v32760
	move/16 v16038, v31679
	move-wide/16 v2195, v10924
	move-object/16 v6347, v25441
	move/16 v10331, v14387
	move/16 v4668, v23548
	move-wide/16 v25008, v3634
	move-wide/16 v6555, v8649
	move/16 v28675, v2722
	move/16 v29511, v22958
	move/16 v6961, v924
	move-wide/16 v23840, v9648
	move-wide/16 v13579, v12762
	move-object/16 v13752, v14262
	move/16 v8271, v27869
	move-wide/16 v3536, v23091
	move-wide/16 v3756, v17749
	move/16 v6382, v27373
	move/16 v7449, v21583
	move-wide/16 v12119, v25057
	move/16 v14267, v15179
	move-object/16 v17900, v4541
	move-object/16 v25831, v19562
	move-object/16 v13225, v19262
	move-object/16 v27697, v15584
	move/16 v11793, v12482
	move-wide/16 v28287, v24966
	move/16 v11355, v13980
	move-wide/16 v18563, v22688
	move/16 v20796, v32238
	move-object/16 v26422, v6315
	move-wide/16 v28628, v13099
	move/16 v6010, v27723
	move/16 v13726, v20202
	move-object/16 v12249, v19600
	move-object/16 v10388, v3562
	move-object/16 v2339, v29131
	move/16 v10149, v23283
	move-wide/16 v18311, v23441
	move-wide/16 v12511, v12285
	move-wide/16 v26686, v32760
	move/16 v24247, v29704
	move/16 v29713, v4586
	move/16 v16273, v15612
	move/16 v11588, v6653
	move-object/16 v21306, v7532
	move/16 v32299, v20796
	move-wide/16 v5575, v29937
	move/16 v8994, v28971
	move-wide/16 v28094, v23686
	move/16 v30783, v31789
	move/16 v12421, v15761
	move-wide/16 v13323, v23441
	move-wide/16 v2064, v16751
	move/16 v25914, v17679
	move/16 v31310, v17774
	move-wide/16 v13726, v24939
	move-object/16 v7118, v445
	move-wide/16 v5403, v11376
	move/16 v5943, v19958
	move-object/16 v10265, v25441
	move-wide/16 v17786, v13707
	move-wide/16 v25645, v2907
	move/16 v10151, v24344
	move/16 v21975, v12028
	move/16 v4253, v26502
	move-object/16 v1231, v17900
	move-wide/16 v24195, v32239
	move/16 v29727, v25914
	move-wide/16 v28586, v31564
	move-wide/16 v14001, v14537
	move/16 v17475, v25846
	move/16 v20079, v4847
	move-object/16 v1201, v9249
	move-wide/16 v5134, v26233
	move-wide/16 v1878, v12689
	move-wide/16 v7005, v4037
	move/16 v32348, v19296
	move-wide/16 v11618, v13857
	move/16 v12275, v9582
	move/16 v12013, v11793
	move/16 v9283, v7252
	move/16 v8777, v29360
	move-wide/16 v6653, v3820
	move-wide/16 v13289, v2285
	move-wide/16 v31723, v2811
	move/16 v19161, v20863
	move/16 v14327, v25703
	move-wide/16 v23660, v19201
	move/16 v15797, v11933
	move-wide/16 v32534, v7818
	move-wide/16 v30728, v9164
	move/16 v20644, v30311
	move/16 v7045, v18675
	move-object/16 v30738, v10958
	move/16 v28239, v30945
	move-wide/16 v11368, v5616
	move/16 v9587, v8401
	move-wide/16 v31676, v24195
	move-wide/16 v26829, v3651
	move/16 v12230, v26113
	move/16 v1397, v23862
	move-object/16 v19189, v28547
	move-wide/16 v8353, v10990
	move/16 v11803, v9872
	move-wide/16 v5227, v15366
	move/16 v21736, v10551
	move-object/16 v13508, v28578
	move/16 v20181, v19828
	move/16 v12962, v13177
	move/16 v7105, v29619
	move/16 v10237, v23830
	move-wide/16 v5524, v28974
	move/16 v16340, v22168
	move-wide/16 v10403, v20270
	move/16 v10802, v20418
	move-wide/16 v21106, v21984
	move/16 v11803, v21919
	move/16 v29024, v24432
	move-object/16 v22130, v15235
	move/16 v27545, v7930
	move/16 v12923, v27360
	move/16 v19201, v29803
	move-wide/16 v12557, v30471
	move/16 v28094, v20181
	move-wide/16 v11554, v10874
	move/16 v19370, v6075
	move/16 v9208, v3175
	move-object/16 v14683, v2093
	move-wide/16 v14510, v10645
	move-object/16 v29750, v923
	move-object/16 v22562, v24977
	move/16 v6843, v10229
	move/16 v22838, v22104
	move-wide/16 v453, v2683
	move-wide/from16 v33, v16192
	move/16 v23459, v14040
	move-wide/16 v13117, v27838
	move/16 v29961, v12302
	move-wide/16 v1673, v27066
	move/16 v24291, v26161
	move/16 v16654, v29288
	move/16 v26566, v553
	move-wide/16 v8526, v16032
	move-wide/16 v21369, v9132
	move/16 v21536, v32179
	move-wide/16 v14452, v26273
	move/16 v14827, v10865
	move-wide/16 v4604, v6218
	move/16 v21736, v1465
	move-wide/16 v23926, v10564
	move/16 v7628, v20584
	move/16 v13487, v11793
	move/16 v25340, v19559
	move-wide/16 v19126, v19193
	move-object/16 v15960, v8000
	move-wide/16 v18294, v20432
	move/16 v293, v8877
	move-wide/16 v24075, v1971
	move-wide/16 v669, v23552
	move-object/16 v27708, v5583
	move/16 v32534, v9322
	move-wide/16 v14276, v16901
	move-object/16 v28759, v19562
	move-wide/16 v19382, v18999
	move-wide/16 v18651, v15446
	move-object/16 v3932, v14396
	move/16 v21106, v26841
	move-object/16 v24204, v15960
	move-wide/16 v15951, v19917
	move/16 v25803, v12745
	move-wide/16 v8391, v15366
	move/16 v271, v4586
	move-object/16 v25731, v488
	move/16 v30105, v16273
	move-object/16 v3735, v3562
	move/16 v18137, v11588
	move/16 v11620, v25482
	move/16 v1033, v23713
	move-wide/16 v13552, v9477
	move/16 v17839, v4462
	move/16 v3490, v26563
	move/16 v13622, v27869
	move-object/16 v7000, v4750
	move/16 v29831, v30666
	move-wide/16 v29940, v24031
	move/16 v23420, v16092
	move/16 v3730, v26556
	move/16 v13718, v7930
	move-wide/16 v2913, v19301
	move/16 v27461, v9249
	move/16 v17359, v31731
	move/16 v6065, v28881
	move/16 v10176, v30503
	move/16 v28049, v32418
	move-wide/16 v23073, v26418
	move/16 v22600, v12626
	move/16 v7212, v18462
	move/16 v19929, v24710
	move-wide/16 v6854, v4037
	move/16 v7185, v1157
	move-wide/16 v11900, v31185
	move/16 v9043, v14519
	move/16 v3419, v14891
	move/16 v30652, v27026
	move-wide/16 v671, v10219
	move/16 v17991, v11788
	move/16 v8777, v23618
	move/16 v26024, v14161
	move-wide/16 v5186, v3651
	move-wide/16 v16352, v25633
	move/16 v15375, v16273
	move-object/16 v30446, v30905
	move/16 v15115, v22720
	move-wide/16 v7435, v11368
	move-object/16 v6442, v2953
	move/16 v30232, v13064
	move/16 v7970, v29418
	move/16 v14919, v32158
	move/16 v21064, v7601
	move-wide/16 v10403, v14434
	move-wide/16 v15481, v18929
	move/16 v19067, v7156
	move-object/16 v23872, v27117
	move-wide/16 v5774, v25746
	move/16 v10491, v4429
	move-wide/16 v26472, v27161
	move/16 v26365, v4290
	move/16 v4859, v5246
	move/16 v14540, v30270
	move-object/16 v13544, v32559
	move-object/16 v7269, v30406
	move-object/16 v19978, v9623
	move-object/16 v26844, v31598
	move/16 v28748, v23698
	move-wide/16 v22357, v10188
	move-wide/16 v4604, v20868
	move-object/16 v792, v13441
	move/16 v4388, v3087
	move/16 v441, v31981
	move-wide/16 v1579, v26704
	move/16 v8685, v22084
	move/16 v11548, v15489
	move/16 v21406, v21666
	move/16 v17659, v19964
	move-object/16 v18642, v31954
	move-object/16 v17096, v19129
	move/from16 v121, v22574
	move/16 v18610, v2172
	move/16 v13601, v8685
	move/16 v12313, v10527
	move-wide/16 v31001, v3291
	move-object/16 v10898, v32391
	move-wide/16 v5376, v6783
	move-wide/16 v5336, v16632
	move-object/16 v20038, v31337
	move-wide/16 v6208, v24420
	move-object/16 v10074, v8699
	move/16 v2295, v21968
	move/16 v25482, v15849
	move-wide/16 v21481, v26499
	move/16 v10389, v5452
	move-wide/16 v5415, v6854
	move/16 v2638, v19974
	move/16 v4270, v20997
	move/16 v28622, v1769
	move/16 v28767, v25537
	move-wide/16 v7930, v2683
	move-wide/16 v26879, v9318
	move/16 v17071, v13808
	move-object/16 v9764, v15235
	move-object/16 v18473, v6850
	move-wide/16 v30833, v2883
	move/16 v16170, v6100
	move/16 v31233, v8209
	move-wide/16 v3308, v17786
	move/from16 v138, v16360
	move-object/16 v324, v13091
	move-object/16 v21028, v8289
	move-object/16 v21868, v14683
	move-wide/16 v28275, v22785
	move-object/16 v2883, v7772
	move/16 v30004, v13029
	move-wide/16 v3049, v10534
	move-wide/16 v20324, v22357
	move/16 v23418, v28386
	move-wide/16 v20437, v6081
	move-wide/16 v24733, v10941
	move/16 v28303, v15983
	move/16 v20466, v12164
	move-wide/16 v9104, v29530
	move-wide/16 v2495, v12501
	move-object/16 v31553, v13225
	move-wide/16 v5363, v10716
	move-object/16 v12437, v3145
	move/16 v23600, v7105
	move/16 v9476, v32020
	move/16 v445, v30105
	move/16 v5496, v21064
	move/16 v30611, v29054
	move-wide/16 v26228, v7990
	move/16 v7557, v20466
	move-object/16 v10716, v17510
	move/16 v11368, v10353
	move-wide/16 v13305, v30714
	move/16 v19856, v4804
	move/16 v26972, v15659
	move/16 v26678, v1529
	move/16 v32769, v17659
	move-wide/16 v25342, v23436
	move/16 v7886, v20158
	move/16 v29471, v9250
	move-object/16 v19249, v21135
	move-wide/16 v30009, v12715
	move-object/16 v25819, v27378
	move/16 v15271, v31523
	move-wide/16 v6577, v2195
	move/16 v7970, v12183
	move/16 v1067, v11332
	move/16 v19661, v20218
	move/16 v19453, v31310
	move/16 v8264, v15581
	move/16 v8673, v31131
	move-object/16 v25474, v2883
	move/16 v16299, v9249
	move-wide/16 v24193, v31185
	move/16 v26844, v12698
	move-wide/16 v20617, v30838
	move/16 v6973, v3884
	move/16 v25647, v26480
	move/16 v28971, v26480
	move-wide/16 v27360, v13579
	move-wide/16 v31004, v9197
	move/16 v3937, v6470
	move/16 v14752, v4839
	move/16 v23944, v18077
	move/16 v2752, v22776
	move-wide/16 v15736, v3978
	move/16 v2495, v23680
	move-wide/16 v18928, v23213
	move-object/16 v26536, v19429
	move/16 v20834, v6382
	move-wide/16 v8233, v15544
	move/16 v1247, v28296
	move/16 v18227, v6065
	move/16 v23713, v31954
	move-wide/16 v13345, v9385
	move/16 v19370, v27742
	move/16 v7281, v19600
	move/16 v19490, v2809
	move-object/16 v29619, v13441
	move/16 v9039, v29276
	move-object/16 v29674, v5478
	move-wide/16 v19894, v5376
	move/16 v29870, v158
	move-wide/16 v7045, v13267
	move/16 v18013, v11782
	move-wide/16 v30209, v7021
	move/16 v28578, v26563
	move-object/16 v19661, v26556
	move-wide/16 v30069, v3756
	move/16 v8788, v14505
	move/16 v29054, v19296
	move-object/16 v10688, v30738
	move-wide/16 v3622, v18563
	move/16 v32377, v26844
	move-object/16 v4541, v792
	move/16 v23130, v32193
	move-wide/16 v6100, v1753
	move-wide/16 v16863, v30752
	move/16 v21552, v28675
	move-object/16 v29780, v14626
	move-wide/from16 v158, v29937
	move/16 v2001, v15476
	move/16 v9173, v16649
	move-wide/16 v25857, v25076
	move/16 v1938, v17679
	move-wide/16 v9582, v6852
	move-wide/16 v29968, v4208
	move-wide/16 v12885, v7021
	move/16 v21806, v27101
	move/16 v13165, v28767
	move/16 v6511, v5943
	move-wide/16 v16291, v21367
	move-wide/16 v16277, v16739
	move/16 v14001, v6298
	move/16 v15993, v9065
	move-wide/16 v15115, v32061
	move-wide/16 v18481, v14466
	move-wide/16 v31839, v17802
	move/16 v6961, v23596
	move/16 v1490, v4248
	move-wide/16 v16852, v28911
	move/16 v13870, v26885
	move-wide/16 v1575, v7073
	move-wide/16 v7974, v15998
	move-wide/16 v10212, v22780
	move/16 v1575, v31789
	move-wide/16 v30356, v6852
	move/16 v23264, v8777
	move/16 v19098, v10580
	move/16 v1756, v2010
	move/16 v32127, v9039
	move/16 v14626, v23997
	move-wide/16 v7838, v20505
	move/16 v13579, v1067
	move-wide/16 v208, v1605
	move/16 v27286, v28597
	move/16 v17506, v6026
	move-wide/16 v16780, v12762
	move/16 v548, v8508
	move-wide/16 v25880, v21681
	move-wide/16 v11355, v10219
	move/16 v28755, v22776
	move-wide/16 v31723, v7646
	move/16 v1102, v19679
	move/16 v23616, v5354
	move/16 v29762, v17201
	move/16 v15981, v29736
	move-object/16 v32127, v18036
	move/16 v14276, v12249
	move-object/16 v8474, v17723
	move-wide/16 v8937, v17348
	move/16 v26845, v1127
	move/16 v24589, v7153
	move/16 v21668, v2593
	move-wide/16 v5336, v5403
	move/16 v13892, v16038
	move-object/16 v23268, v31553
	move-object/16 v17455, v22828
	move/16 v23486, v2
	move-object/16 v30886, v29750
	move/16 v23265, v16553
	move-object/16 v17396, v3875
	move-wide/16 v14040, v26704
	move/16 v30742, v10527
	move-wide/16 v9010, v15446
	move-wide/16 v23511, v23303
	move-object/16 v14683, v1231
	move-wide/16 v30200, v22293
	move/16 v23270, v8216
	move-wide/16 v6590, v25076
	move-wide/16 v19201, v5415
	move/16 v18041, v3783
	move/16 v4943, v15229
	move-wide/16 v12458, v23105
	move-wide/16 v5429, v16102
	move-wide/16 v10388, v18294
	move-wide/16 v20868, v13796
	move-wide/16 v30398, v24922
	move/16 v4975, v276
	move-wide/16 v18253, v24327
	move/16 v1357, v17071
	move/16 v4032, v26003
	move/16 v19323, v11517
	move-wide/16 v29209, v25572
	move/16 v28594, v15357
	move-object/16 v18311, v5140
	move-object/16 v4993, v11744
	move/16 v27217, v23226
	move-object/16 v22315, v11928
	move-wide/16 v31982, v432
	move-wide/16 v30965, v30256
	move/16 v23975, v28622
	move/16 v18511, v26845
	move/16 v32016, v19161
	move/16 v4943, v1638
	move/16 v19481, v7427
	move-wide/16 v27352, v21984
	move/16 v31202, v946
	move-wide/16 v7732, v29937
	move/16 v8186, v7428
	move/16 v9476, v26893
	move/16 v6065, v11521
	move-wide/16 v6123, v7073
	move/16 v10260, v15375
	move-object/16 v8832, v10958
	move-wide/16 v21457, v20822
	move/16 v23872, v31691
	move/16 v26704, v29024
	move/16 v5908, v20482
	move-wide/16 v8483, v16852
	move-wide/16 v3490, v432
	move/16 v14327, v13888
	move-object/16 v7914, v27640
	move-wide/16 v20697, v14582
	move-object/16 v23883, v18273
	move/16 v26798, v23082
	move-wide/16 v27495, v12458
	move/16 v11166, v4668
	move-wide/16 v11243, v28871
	move/16 v24718, v1033
	move/16 v9959, v3012
	move-wide/16 v31310, v22785
	move-object/16 v6471, v24919
	move/16 v27077, v18417
	move-object/16 v6709, v15235
	move/16 v14927, v13569
	move-object/16 v3562, v9764
	move-wide/16 v22238, v14013
	move-wide/16 v304, v12762
	move/16 v22084, v6979
	move/16 v27249, v8694
	move-object/16 v21721, v20889
	move-wide/16 v21418, v31839
	move/16 v5456, v1357
	move/16 v13226, v23052
	move-wide/16 v27376, v3725
	move/16 v10924, v20644
	move-wide/16 v1943, v12937
	move/16 v24397, v5541
	move-wide/16 v2850, v32627
	move-wide/16 v25914, v29324
	move-wide/16 v15981, v10370
	move-wide/16 v18539, v20531
	move-wide/16 v31723, v26829
	move/16 v14396, v21138
	move-object/16 v4133, v14005
	move/16 v16428, v4805
	move/16 v11578, v928
	move-object/16 v19281, v7898
	move-object/16 v24802, v12971
	move-wide/16 v28642, v15201
	move-wide/16 v15803, v7637
	move-wide/16 v27892, v5042
	move/16 v16133, v2800
	move/16 v19004, v25482
	move-object/16 v13544, v14683
	move/16 v13990, v9685
	move-object/16 v7545, v28547
	move-wide/16 v15102, v19301
	move/16 v23653, v10353
	move/16 v30004, v19048
	move-wide/16 v18802, v4573
	move/16 v31337, v10237
	move-object/16 v7428, v7451
	move/16 v30833, v15229
	move-wide/16 v4723, v19411
	move-object/16 v30525, v20525
	move-object/16 v28982, v21866
	move/16 v11516, v30874
	move-wide/16 v16506, v28640
	move/16 v20247, v29024
	move-object/16 v24589, v9552
	move-object/16 v1529, v30674
	move-object/16 v18486, v24977
	move-object/from16 v165, v31089
	move-object/16 v29146, v3730
	move/16 v5174, v32183
	move-wide/16 v8481, v24791
	move/16 v25731, v2010
	move/16 v4319, v23423
	move/16 v5976, v12965
	move/16 v13340, v30783
	move/16 v1999, v10320
	move/16 v11900, v1713
	move-object/16 v9525, v32186
	move/16 v12142, v13340
	move/16 v19961, v16968
	move-object/16 v11397, v5391
	move/16 v29689, v20153
	move-wide/16 v22682, v4651
	move-wide/16 v18968, v6081
	move-wide/16 v20236, v18145
	move/16 v7169, v17798
	move-object/16 v5963, v27252
	move-wide/16 v18094, v16632
	move-wide/16 v32041, v3634
	move/16 v18774, v21677
	move-object/16 v2247, v2620
	move/16 v22562, v22082
	move/16 v31020, v8214
	move-object/16 v14327, v22158
	move/16 v25828, v14650
	move/16 v24148, v23558
	move-wide/16 v20337, v26330
	move/16 v30231, v27654
	move/16 v3009, v252
	move-wide/16 v138, v26418
	move-wide/16 v30864, v4208
	move-object/16 v18374, v19060
	move-wide/16 v11242, v3308
	move/16 v29418, v6661
	move-wide/16 v15149, v21367
	move/16 v20434, v9422
	move-wide/16 v2610, v15161
	move/16 v8401, v24912
	move-object/16 v22293, v852
	move/16 v5259, v14276
	move/16 v31441, v19989
	move-object/16 v20596, v13569
	move-wide/16 v18033, v3291
	move-object/16 v6783, v20153
	move-object/16 v12518, v19600
	move/16 v14747, v16941
	move-object/16 v4887, v11744
	move/16 v26893, v23600
	move/16 v27252, v18013
	move-object/16 v10491, v23883
	move/16 v13943, v29471
	move-object/16 v21542, v5981
	move/16 v27228, v1960
	move-object/16 v28409, v9552
	move/16 v10700, v23862
	move/from16 v219, v28755
	move-wide/from16 v73, v3634
	move/16 v30783, v4784
	move/16 v26373, v5588
	move-object/16 v8768, v9623
	move-wide/16 v2136, v12147
	move/16 v7385, v14750
	move-wide/16 v4194, v2697
	move-object/16 v3098, v18722
	move-object/16 v8872, v9735
	move/16 v18659, v1287
	move-object/16 v15469, v7113
	move-wide/16 v29155, v30282
	move/16 v25808, v23830
	move-object/16 v29838, v10439
	move-object/16 v324, v12282
	move-wide/16 v9310, v15803
	move-wide/16 v8031, v7732
	move/16 v30886, v19296
	move/16 v9977, v18118
	move-wide/16 v931, v5706
	move/16 v2774, v27344
	move-object/16 v12611, v19419
	move/16 v9213, v14783
	move-object/16 v26057, v19652
	move/16 v8054, v29762
	move/16 v29563, v19161
	move/16 v22779, v11982
	move-wide/16 v27955, v18734
	move-object/16 v27034, v15925
	move-wide/16 v1102, v25251
	move-wide/16 v18137, v10676
	move-wide/16 v22523, v10990
	move-wide/16 v19750, v14219
	move/16 v3234, v7156
	move-wide/16 v3720, v4561
	move-wide/16 v7218, v476
	move-wide/16 v4889, v12937
	move-wide/16 v6881, v12501
	move/16 v6748, v20622
	move/from16 v252, v20153
	move-wide/16 v16335, v23213
	move/16 v18158, v19652
	move-object/16 v15983, v10688
	move/16 v19058, v25994
	move-wide/16 v20218, v12824
	move-wide/16 v30652, v5575
	move-object/16 v15558, v24380
	move-wide/16 v9959, v25263
	move/16 v8832, v23283
	move/16 v30781, v20691
	move-wide/16 v9685, v26127
	move-wide/16 v12147, v27066
	move-object/16 v2976, v20794
	move/16 v30300, v3098
	move-wide/16 v28223, v10874
	move-object/16 v2285, v12611
	move-object/16 v27787, v24380
	move/16 v28948, v17401
	move/16 v9261, v634
	move-wide/16 v20420, v15568
	move/16 v29559, v25542
	move/16 v32666, v28449
	move-object/16 v19628, v6415
	move/16 v32183, v32183
	move-wide/16 v28401, v8475
	move/16 v30576, v12537
	move/16 v28409, v16688
	move/16 v17809, v22197
	move/16 v25814, v21983
	move-wide/16 v4432, v28640
	move-wide/16 v13452, v29928
	move/16 v31240, v21446
	move/16 v16947, v32650
	move-wide/16 v10650, v7440
	move-wide/16 v12038, v21369
	move-wide/16 v29003, v6881
	move-wide/16 v31176, v29324
	move-object/16 v7483, v19652
	move-wide/16 v9365, v24195
	move/16 v21310, v20067
	move/16 v8103, v8271
	move/16 v18511, v8832
	move/16 v13452, v26365
	move-object/16 v14005, v19249
	move-object/16 v20712, v4077
	move-wide/16 v24846, v24643
	move-object/16 v10385, v10641
	move/16 v6096, v16428
	move-wide/from16 v2, v580
	move/16 v28723, v28767
	move/16 v27952, v1769
	move/16 v15066, v7963
	move/16 v5559, v28469
	move/16 v14463, v15849
	move-wide/16 v24587, v26273
	move/16 v12275, v32208
	move/16 v8699, v32645
	move/16 v15750, v23830
	move/16 v10952, v4568
	move-wide/16 v27212, v24955
	move-wide/16 v1397, v20931
	move/16 v27117, v29831
	move/16 v31598, v785
	move-object/16 v22828, v4255
	move/16 v3726, v7499
	move-object/16 v30446, v14936
	move-wide/16 v24807, v23495
	move-wide/16 v23153, v32632
	move/16 v3615, v27723
	move-object/16 v2835, v10716
	move/16 v5600, v13906
	move/16 v10482, v15659
	move/16 v27697, v17278
	move/16 v8045, v10294
	move/16 v31025, v18978
	move/16 v17138, v15797
	move-object/16 v8872, v1909
	move-wide/16 v22445, v23511
	move-object/16 v29552, v17876
	move-object/from16 v150, v13752
	move/16 v11058, v10962
	move-object/16 v24011, v21850
	move/16 v3764, v488
	move-object/16 v2774, v18273
	move-wide/16 v12717, v18014
	move/16 v26732, v31034
	move/16 v28519, v9283
	move/16 v16273, v19226
	move/16 v3049, v24912
	move-object/16 v16654, v11744
	move-wide/16 v23441, v11219
	move/16 v26898, v15307
	move-wide/16 v28636, v3330
	move/16 v31940, v8685
	move/16 v2820, v7630
	move-object/16 v21342, v516
	move-wide/16 v3138, v15568
	move/16 v17679, v18455
	move/16 v4898, v9064
	move-object/16 v27410, v13091
	move-wide/16 v3238, v31310
	move-object/16 v19201, v28143
	move-object/16 v23874, v13225
	move-wide/16 v31815, v13113
	move/16 v3490, v20153
	move/16 v16585, v19974
	move-wide/16 v15489, v27242
	move-wide/16 v24515, v22688
	move-object/16 v19904, v10641
	move/16 v30325, v12537
	move-object/16 v6087, v2774
	move/16 v16100, v30056
	move/16 v19673, v32016
	move/16 v26161, v23707
	move-wide/16 v7794, v17780
	move-wide/16 v15885, v14609
	move-wide/16 v17211, v138
	move-wide/16 v12038, v7674
	move-object/16 v6163, v4077
	move/16 v9105, v23862
	move/16 v21310, v5981
	move/16 v27807, v17538
	move/16 v3349, v18267
	move/16 v374, v21983
	move-wide/16 v3840, v25857
	move-wide/16 v13091, v27331
	move-object/16 v5588, v29088
	move-object/16 v1033, v10688
	move-wide/16 v12302, v21605
	move-wide/16 v25310, v14609
	move/16 v16941, v26857
	move/16 v25282, v16579
	move/16 v27639, v19844
	move-wide/16 v20860, v20764
	move-wide/16 v13622, v28401
	move/16 v15375, v29526
	move-object/16 v24372, v21866
	move/16 v13892, v8329
	move/16 v11660, v14200
	move-wide/16 v26069, v9831
	move/16 v28597, v19989
	move-wide/16 v28254, v24842
	move/16 v20505, v1306
	move-object/16 v12965, v21126
	move/16 v20243, v7797
	move-wide/16 v24669, v27138
	move-wide/16 v20634, v2407
	move/16 v29710, v11960
	move-wide/16 v23436, v21669
	move/16 v25846, v19628
	move-wide/16 v17510, v12395
	move/16 v25703, v7483
	move-object/16 v3687, v22764
	move-wide/16 v26928, v18651
	move/16 v16258, v8994
	move-wide/16 v23082, v26127
	move/16 v10243, v28201
	move-wide/16 v2785, v16032
	move/16 v26954, v19673
	move-object/16 v24304, v13266
	move-object/16 v19098, v22315
	move-wide/16 v21583, v20337
	move-object/16 v32729, v1298
	move-object/16 v10688, v8768
	move-wide/16 v29713, v21904
	move/16 v2809, v24905
	move/16 v4719, v677
	move/16 v15912, v23997
	move/16 v7169, v10839
	move-wide/16 v12343, v5517
	move-wide/16 v24955, v27495
	move/16 v29482, v3643
	move-wide/16 v16510, v2104
	move/16 v30161, v13888
	move-object/16 v20224, v25831
	move-wide/16 v26564, v9365
	move/16 v10411, v240
	move/16 v22090, v29627
	move-wide/16 v30256, v11556
	move-wide/16 v27066, v31815
	move/16 v15685, v1811
	move/16 v5890, v32768
	move-object/16 v24031, v25846
	move/16 v31564, v18472
	move-object/16 v6367, v7169
	move-wide/16 v12923, v24950
	move-wide/16 v18077, v1109
	move/16 v1298, v29172
	move-wide/16 v15769, v20337
	move-object/16 v27101, v11064
	move/16 v31275, v20796
	move/16 v20034, v14161
	move/16 v14616, v24695
	move/16 v30635, v4568
	move-wide/16 v29858, v20868
	move/16 v14912, v3082
	move/16 v21306, v8225
	move-object/16 v2724, v13015
	move-wide/16 v17714, v7732
	move/16 v21580, v15139
	move/16 v14862, v28734
	move-object/16 v24486, v18630
	move/16 v8214, v10611
	move-wide/16 v8574, v15366
	move/16 v26117, v31955
	move-object/16 v22937, v23312
	move-wide/16 v27708, v10403
	move-wide/16 v650, v5952
	move/16 v1555, v20034
	move-object/16 v18033, v18641
	move-object/16 v3227, v3192
	move/16 v28303, v23548
	move/16 v26590, v2809
	move/16 v812, v23600
	move/16 v9959, v23975
	move/16 v28675, v31900
	move-wide/16 v2497, v24643
	move-wide/16 v8761, v4062
	move-wide/16 v27167, v28287
	move/16 v17774, v10772
	move/16 v32729, v5698
	move-object/16 v476, v5391
	move-wide/16 v11516, v12937
	move/16 v1811, v21440
	move-object/16 v23557, v4993
	move-wide/16 v9384, v12717
	move/16 v18882, v27640
	move-wide/16 v22532, v17802
	move/16 v12773, v16100
	move/16 v6081, v3490
	move-wide/16 v2907, v30009
	move-object/16 v15406, v31475
	move/16 v13483, v31240
	move/16 v4462, v4487
	move-wide/16 v4369, v6974
	move-object/16 v15893, v16654
	move/16 v27983, v14505
	move/16 v18436, v24916
	move/16 v20437, v24710
	move-wide/16 v12482, v25887
	move/16 v26457, v16941
	move-object/16 v23279, v27366
	move-object/16 v20333, v21310
	move-wide/16 v6028, v8483
	move-wide/16 v18193, v11710
	move/16 v24728, v31194
	move-wide/16 v10388, v32632
	move/16 v18289, v19847
	move/16 v26342, v8699
	move/16 v4557, v10151
	move-object/16 v17633, v523
	move-wide/16 v16941, v17802
	move-wide/16 v7666, v18193
	move/16 v14510, v24232
	move/16 v16401, v19312
	move/16 v20243, v13483
	move/16 v9576, v22574
	move/16 v10136, v26373
	move/16 v17369, v11636
	move-wide/16 v26549, v24939
	move-object/16 v31488, v29674
	move-object/16 v23185, v32767
	move/16 v23495, v30874
	move-wide/16 v1287, v16877
	move-wide/16 v20158, v8533
	move-wide/16 v6123, v18077
	move/16 v4709, v12670
	move/16 v2147, v32708
	move/16 v10081, v16461
	move-wide/16 v28251, v5376
	move-wide/16 v8522, v31660
	move-wide/16 v14401, v872
	move/16 v14337, v3881
	move/16 v2492, v30945
	move/16 v276, v23830
	move/16 v28974, v6738
	move-wide/16 v18010, v16639
	move/16 v15794, v785
	move/16 v3475, v24383
	move-object/16 v32361, v12055
	move/16 v3548, v12698
	move-wide/16 v23425, v20531
	move/16 v19876, v23418
	move-wide/16 v52, v3840
	move-wide/16 v4719, v29389
	move/16 v24733, v11211
	move-object/16 v5114, v8825
	move-wide/16 v10611, v7257
	move/16 v2228, v19884
	move/16 v8533, v23043
	move/16 v14936, v9375
	move-wide/16 v9334, v2777
	move-wide/16 v604, v580
	move/16 v30421, v30161
	move/16 v32558, v6324
	move/16 v6347, v19974
	move/16 v8038, v22315
	move/16 v19114, v2182
	move/16 v6790, v15617
	move/16 v13579, v32208
	move-wide/16 v18992, v6374
	move/16 v29923, v32179
	move/16 v27026, v29598
	move-wide/16 v2529, v1971
	move/16 v24452, v15581
	move-wide/16 v27260, v16200
	move-object/16 v13784, v32767
	move-object/16 v7977, v2285
	move/16 v21542, v29526
	move/16 v19998, v30270
	move-wide/16 v293, v17562
	move-object/16 v24824, v29615
	move/16 v25572, v28085
	move-object/16 v31085, v29071
	move-object/16 v3765, v10032
	move-wide/16 v4305, v2907
	move/16 v32558, v20691
	move-object/16 v28734, v27410
	move-wide/16 v2835, v213
	move/16 v19382, v0
	move-object/16 v7628, v6709
	move-wide/16 v1621, v17749
	move-wide/16 v18986, v21559
	move/16 v923, v9872
	move/16 v11875, v16651
	move-wide/16 v8937, v21926
	move-wide/16 v6790, v23840
	move-object/16 v15834, v11064
	move/16 v9384, v1481
	move-wide/16 v20236, v22761
	move/16 v3951, v31872
	move/16 v10012, v3559
	move/16 v26558, v24728
	move-wide/16 v28572, v30838
	move-wide/16 v1556, v18928
	move/16 v24407, v20836
	move/16 v2060, v747
	move-wide/16 v11782, v24791
	move/16 v24503, v9173
	move-wide/16 v20034, v15885
	move/16 v4219, v20691
	move/16 v26566, v20437
	move/16 v5541, v19830
	move-wide/16 v5595, v9032
	move/16 v28223, v13380
	move-wide/16 v3419, v5575
	move-object/16 v7304, v13266
	move-wide/16 v8761, v32749
	move-wide/16 v28060, v5250
	move-wide/16 v2495, v12343
	move-wide/16 v12506, v3706
	move/16 v31696, v18436
	move-object/16 v4248, v2656
	move/16 v10074, v31025
	move/16 v29079, v10698
	move-wide/16 v32087, v28811
	move-wide/16 v10385, v26923
	move-wide/16 v14421, v14421
	move-wide/16 v8841, v25342
	move-wide/16 v20337, v10139
	move/16 v14582, v16100
	move-wide/16 v2483, v30652
	move-wide/16 v13266, v30790
	move/16 v4573, v28882
	move-wide/16 v8167, v5524
	move-wide/16 v5336, v32225
	move/16 v17809, v4815
	move-object/16 v12510, v9265
	move-wide/16 v32449, v3072
	move/16 v13113, v17985
	move/16 v18488, v25838
	move-object/16 v32428, v14652
	move/16 v6291, v27026
	move-wide/16 v9353, v4062
	move/16 v30307, v2172
	move/16 v18472, v6783
	move-wide/16 v16461, v597
	move/16 v21577, v4855
	move-wide/16 v30307, v18539
	move-wide/16 v27322, v28401
	move/16 v8642, v28971
	move-wide/16 v29187, v2064
	move/16 v6248, v5215
	move/16 v21215, v9322
	move-wide/16 v26549, v8475
	move-wide/16 v21935, v20822
	move/16 v13340, v6115
	move-object/16 v28223, v28547
	move-object/16 v28767, v29552
	move/16 v9318, v1960
	move-wide/16 v30734, v208
	move/16 v26586, v4689
	move-wide/16 v28526, v2495
	move-object/16 v8602, v32559
	move/16 v14493, v7056
	move/16 v13029, v19891
	move/16 v3082, v21276
	move-wide/16 v23153, v9010
	move/16 v21028, v28430
	move-wide/16 v17444, v30981
	move-object/16 v32363, v25117
	move/16 v12965, v22872
	move/16 v6783, v27655
	move/16 v19953, v19357
	move-wide/16 v21899, v12478
	move/16 v585, v14240
	move/16 v2133, v31564
	move-wide/16 v31723, v1415
	move/16 v15151, v31441
	move-wide/16 v6406, v10990
	move/16 v27461, v28873
	move/16 v2407, v14132
	move-wide/16 v4479, v30282
	move/16 v19006, v17169
	move-wide/16 v21437, v208
	move/16 v1386, v32769
	move-wide/16 v2534, v12592
	move/16 v5465, v26966
	move-wide/16 v31618, v4369
	move-wide/16 v6862, v30752
	move-object/16 v27632, v30227
	move/16 v11601, v17679
	move/16 v21393, v8306
	move-wide/16 v2325, v1753
	move/16 v23616, v30759
	move/16 v20058, v6382
	move/16 v10012, v28723
	move/16 v16852, v26893
	move-object/16 v1618, v4947
	move/16 v28285, v30742
	move-object/16 v27373, v15584
	move-object/16 v2900, v9066
	move/16 v27261, v7754
	move/16 v4784, v8497
	move-wide/16 v7786, v453
	move-wide/16 v28934, v13091
	move-wide/16 v18972, v15366
	move-object/16 v18999, v24018
	move/16 v6814, v14876
	move-wide/16 v24347, v6100
	move/16 v31859, v19844
	move-wide/16 v10476, v29858
	move/16 v27461, v17201
	move-wide/16 v31910, v30398
	move-wide/16 v30645, v15481
	move-wide/16 v13717, v24538
	move-object/16 v3308, v28982
	move-wide/16 v10621, v1732
	move-object/16 v13882, v27373
	move-wide/16 v27161, v27322
	move/16 v5616, v28882
	move/16 v18130, v24905
	move-object/16 v17506, v4586
	move/16 v4001, v23486
	move/16 v6577, v15834
	move-wide/16 v20123, v7838
	move-wide/16 v14562, v5866
	move/16 v29342, v10865
	move-wide/16 v30290, v18651
	move/16 v11916, v7187
	move-wide/16 v374, v9477
	move/16 v1411, v24926
	move-wide/16 v931, v6028
	move/16 v16813, v8647
	move/16 v31337, v9576
	move/16 v30783, v10531
	move-wide/16 v29017, v728
	move-object/16 v4036, v1523
	move-object/16 v29117, v4540
	move-wide/16 v27242, v26047
	move/16 v19357, v23862
	move-wide/16 v14562, v16769
	move-wide/16 v15750, v23082
	move-object/16 v32636, v2620
	move-wide/16 v10464, v28572
	move-wide/16 v27825, v13552
	move-wide/16 v4689, v30298
	move-object/16 v3330, v8251
	move/16 v5890, v31523
	move/16 v27736, v26798
	move/16 v11812, v26738
	move-object/16 v12885, v13441
	move-wide/16 v31789, v5227
	move/16 v24788, v23226
	move/16 v22611, v28085
	move-wide/16 v25028, v10941
	move-wide/16 v32449, v24955
	move-wide/16 v8497, v24499
	move/16 v27277, v29526
	move-wide/16 v5593, v28351
	move/16 v27146, v24695
	move-object/16 v22884, v13882
	move-wide/16 v12467, v15443
	move/16 v18843, v19830
	move-wide/16 v32728, v18331
	move-object/16 v15066, v9735
	move/16 v29891, v29627
	move-wide/16 v25342, v24499
	move-wide/16 v30227, v28060
	move/16 v32558, v15229
	move/16 v4307, v23459
	move-wide/16 v25063, v5706
	move-object/16 v21215, v8818
	move/16 v26373, v8877
	move/16 v16360, v28882
	move/16 v10209, v18843
	move-wide/16 v3337, v30026
	move/16 v10486, v8401
	move-object/16 v24589, v26621
	move/16 v8522, v14633
	move/16 v13677, v31278
	move-object/16 v1287, v6471
	move-object/16 v3019, v14683
	move/16 v29765, v32299
	move/16 v1922, v16553
	move-wide/16 v24587, v29952
	move/16 v29627, v6347
	move/16 v11458, v747
	move-wide/16 v5409, v29187
	move/16 v25285, v6979
	move-object/16 v27161, v21464
	move/16 v27066, v15903
	move-wide/16 v24587, v17593
	move/16 v12596, v10700
	move/16 v17924, v11840
	move/16 v1908, v29079
	move-object/16 v4388, v21721
	move-object/16 v28971, v17524
	move/16 v14026, v31194
	move-object/16 v14434, v25474
	move-wide/16 v3962, v6374
	move-wide/16 v29952, v23926
	move/16 v4319, v553
	move/16 v25696, v8685
	move-wide/16 v26930, v32155
	move/16 v3765, v8508
	move-wide/16 v31739, v26564
	move-wide/16 v9601, v783
	move/16 v12762, v4898
	move/16 v28640, v14026
	move-wide/16 v30421, v24038
	move/16 v12826, v15903
	move/16 v14013, v28713
	move-object/16 v13178, v30639
	move-wide/16 v18968, v14339
	move-wide/16 v5250, v14659
	move-wide/16 v31004, v18193
	move/16 v15849, v6511
	move-object/16 v11928, v32086
	move-wide/16 v1386, v9644
	move-object/16 v12358, v13569
	move-object/16 v16654, v23252
	move-wide/16 v28974, v1095
	move-wide/16 v26845, v15568
	move/16 v10136, v12032
	move-object/16 v13693, v17506
	move-wide/16 v22530, v5760
	move/16 v32774, v26365
	move/16 v16196, v19998
	move/16 v20270, v25118
	move/16 v4760, v30004
	move-wide/16 v29803, v28648
	move-object/16 v19453, v31358
	move-wide/16 v30898, v8649
	move-object/16 v8216, v2976
	move-object/16 v10151, v32333
	move/16 v30517, v3357
	move-wide/16 v4815, v19301
	move/16 v8948, v548
	move-object/from16 v240, v19060
	move/16 v10421, v29482
	move-wide/16 v23670, v31982
	move/16 v27167, v24422
	move-wide/16 v4828, v26472
	move-wide/16 v11020, v27917
	move-object/16 v18674, v10580
	move/16 v10932, v23944
	move-object/16 v6730, v22130
	move/16 v1981, v17659
	move/16 v12001, v9959
	move/16 v20219, v24273
	move/16 v1800, v24832
	move/16 v15481, v1108
	move-object/16 v16877, v9514
	move-wide/16 v20418, v13728
	move/16 v8256, v25340
	move/16 v24787, v6257
	move/16 v17659, v26558
	move-wide/16 v23066, v29107
	move-object/16 v25598, v4661
	move/16 v26353, v10110
	move-wide/16 v9582, v32760
	move-wide/16 v26472, v19103
	move-object/16 v32181, v28148
	move-wide/16 v8841, v10941
	move/16 v15903, v8214
	move-object/16 v3500, v24077
	move-wide/16 v27168, v23686
	move-wide/16 v21406, v26879
	move/16 v22245, v7058
	move-wide/16 v16366, v11775
	move/16 v30525, v19365
	move-object/16 v29003, v28143
	move-wide/16 v2132, v7205
	move/16 v26966, v9977
	move-wide/16 v26161, v18294
	move/16 v31131, v634
	move/16 v27356, v23160
	move-wide/16 v23975, v20274
	move-wide/16 v21270, v23144
	move-object/16 v24538, v20224
	move-wide/16 v22948, v31419
	move/16 v22661, v12761
	move/16 v25740, v14177
	move/16 v22168, v10149
	move/16 v31731, v32650
	move-object/16 v25118, v10842
	move-wide/16 v5467, v7062
	move/16 v12720, v13888
	move/16 v21538, v26373
	move-object/16 v13381, v13784
	move/16 v11240, v15925
	move-wide/16 v975, v10611
	move/16 v10551, v2988
	move/16 v13184, v15685
	move/16 v8371, v25740
	move-wide/16 v18879, v14535
	move-object/16 v7956, v7772
	move/16 v25263, v24452
	move/16 v5056, v13177
	move/16 v21481, v13990
	move/16 v31131, v28881
	move-object/16 v18170, v9265
	move-wide/16 v25647, v18294
	move/16 v18374, v17971
	move-wide/16 v5890, v21583
	move-wide/16 v2182, v3274
	move-wide/16 v28578, v9164
	move/16 v13560, v946
	move/16 v17383, v12826
	move-wide/from16 v208, v29811
	move-object/16 v7393, v22846
	move/16 v15469, v14062
	move-wide/16 v32558, v6590
	move/16 v8948, v15179
	move-wide/16 v3579, v73
	move/16 v7005, v13980
	move-wide/16 v28260, v26127
	move-object/16 v31286, v4388
	move/16 v1411, v352
	move/16 v8516, v31869
	move-object/16 v685, v3330
	move/16 v4194, v4036
	move/16 v6852, v8633
	move-wide/16 v9644, v22780
	move-wide/16 v16894, v2073
	move/16 v21812, v32666
	move-wide/16 v30752, v18972
	move-object/16 v5863, v29146
	move/16 v32604, v4760
	move/16 v13328, v27742
	move-wide/16 v6709, v32760
	move-object/16 v8788, v3098
	move/16 v10531, v6065
	move/16 v14658, v31233
	move/16 v19093, v4898
	move-object/16 v17659, v13441
	move-wide/16 v6920, v14401
	move/16 v10381, v24397
	move-object/16 v24077, v17506
	move/16 v1386, v20058
	move-wide/16 v32373, v14391
	move/16 v21367, v2479
	move-object/16 v28548, v9106
	move/16 v31561, v5635
	move/16 v28267, v16813
	move-wide/16 v9064, v29530
	move-wide/16 v28122, v25936
	move-object/16 v19825, v31191
	move/16 v28260, v26117
	move/16 v23160, v32208
	move-wide/16 v19734, v15568
	move/16 v5650, v11211
	move/16 v13345, v32308
	move/16 v7674, v20181
	move/16 v25441, v10320
	move-wide/16 v14927, v3585
	move/16 v8280, v29627
	move-wide/16 v6709, v32749
	move-wide/16 v7673, v5952
	move/16 v6026, v29153
	move/16 v9310, v29563
	move/16 v22725, v1025
	move/16 v8038, v21306
	move/16 v7637, v25499
	move-object/16 v14421, v5114
	move-object/16 v21866, v16651
	move/16 v22392, v785
	move/16 v29918, v1847
	move-object/16 v23277, v13752
	move/16 v10149, v7754
	move/16 v10074, v19600
	move-object/16 v22307, v22661
	move/16 v28223, v26315
	move/16 v4935, v1396
	move-wide/16 v9455, v5376
	move-object/16 v13808, v12510
	move/16 v4290, v11588
	move-wide/16 v6872, v20931
	move-wide/16 v22761, v11710
	move-wide/16 v30738, v3064
	move-wide/16 v27217, v15885
	move/16 v12358, v5259
	move/16 v19699, v523
	move-wide/16 v26399, v19917
	move/16 v6757, v8533
	move/16 v10390, v22838
	move-wide/16 v31553, v15736
	move-object/16 v25474, v1381
	move-wide/16 v31013, v4204
	move-wide/16 v23028, v32632
	move/16 v19734, v3548
	move/16 v2147, v2492
	move-wide/16 v30779, v10468
	move/16 v6295, v16762
	move-wide/16 v23788, v11376
	move-object/16 v13714, v24166
	move/16 v29858, v21446
	move-wide/16 v21981, v25310
	move/16 v13728, v10149
	move/16 v2774, v2809
	move/16 v3840, v28594
	move/16 v11803, v4804
	move/16 v22526, v21536
	move/16 v1909, v13795
	move-object/16 v20420, v13569
	move/16 v31281, v7970
	move/16 v165, v32183
	move-object/16 v29144, v27410
	move/16 v13980, v12698
	move-wide/16 v23276, v6100
	move/16 v8832, v2031
	move/16 v14750, v31954
	move/16 v24230, v2988
	move/from16 v117, v12966
	move-wide/16 v22779, v20657
	move/16 v30783, v23388
	move/16 v25436, v24503
	move-wide/16 v27410, v29952
	move-wide/16 v2687, v22204
	move/16 v15993, v28260
	move-wide/16 v24807, v4204
	move-wide/16 v9358, v6974
	move-wide/16 v1386, v20617
	move/16 v7056, v30152
	move/16 v12028, v4029
	move-object/16 v14806, v3192
	move-wide/16 v32590, v15161
	move-wide/16 v25343, v8649
	move/16 v12252, v1983
	move/16 v23578, v14871
	move/16 v20622, v22661
	move/16 v31176, v14510
	move/16 v6961, v8251
	move/16 v4524, v32708
	move/16 v19164, v8054
	move-wide/16 v29937, v27242
	move-object/16 v23092, v15235
	move/16 v29589, v28201
	move-wide/16 v21968, v17780
	move-wide/16 v8598, v15530
	move-wide/16 v19237, v11710
	move/16 v19894, v31872
	move/16 v10839, v21534
	move-wide/16 v30024, v16291
	move-wide/16 v11710, v23754
	move-wide/16 v4479, v14452
	move/16 v3150, v2896
	move/16 v4604, v2809
	move/16 v3202, v4935
	move-wide/16 v8508, v28287
	move/16 v22459, v23680
	move/16 v22600, v21538
	move-object/16 v8777, v7977
	move-wide/16 v26418, v12689
	move-wide/16 v1769, v16908
	move/16 v6277, v25340
	move-object/16 v23947, v31085
	move-wide/16 v27274, v7045
	move/16 v19365, v31872
	move/16 v28332, v18587
	move/16 v21605, v6324
	move/16 v20686, v25686
	move-wide/16 v32275, v3940
	move/16 v11933, v32193
	move/16 v26472, v6738
	move/16 v23226, v31954
	move-object/16 v18079, v516
	move-wide/16 v24273, v12689
	move-object/16 v10684, v23279
	move/16 v342, v9720
	move-object/16 v11634, v25831
	move-object/16 v31004, v23185
	move/16 v2610, v11588
	move-object/16 v14609, v8818
	move-wide/16 v26161, v21119
	move/16 v7722, v13345
	move/16 v31561, v10865
	move-wide/16 v20711, v21926
	move/16 v21968, v26411
	move/16 v4131, v1490
	move-wide/16 v10353, v8841
	move/16 v29659, v12028
	move/16 v16026, v12626
	move-wide/16 v11578, v2811
	move/16 v23872, v31034
	move-wide/16 v30484, v19496
	move/16 v5250, v7517
	move/16 v14650, v24787
	move/16 v2722, v7898
	move/16 v6305, v29923
	move/16 v19141, v21276
	move/16 v5732, v924
	move-wide/16 v7172, v16380
	move-wide/16 v26365, v31910
	move-wide/16 v16055, v22785
	move/16 v22884, v12965
	move-object/16 v18014, v10491
	move-wide/16 v10534, v13775
	move/16 v24905, v21440
	move-wide/16 v26003, v18968
	move/16 v13443, v16196
	move-object/16 v13728, v9735
	move-wide/16 v26899, v7021
	move-wide/16 v11269, v2835
	move-wide/16 v22019, v30209
	move-wide/16 v374, v18819
	move-wide/16 v23557, v15378
	move-object/16 v4906, v20067
	move-wide/16 v29471, v6498
	move-wide/16 v4604, v28275
	move/16 v8883, v8103
	move/16 v29344, v5982
	move/16 v31004, v26563
	move/16 v17071, v31636
	move/16 v19161, v24422
	move-wide/16 v28609, v6590
	move/16 v9598, v23678
	move/16 v7593, v9250
	move/16 v5593, v13064
	move/16 v19884, v29153
	move/16 v25111, v17991
	move-wide/16 v2182, v29107
	move/16 v32228, v1306
	move-object/16 v21563, v6714
	move/16 v7630, v7212
	move/16 v2623, v19953
	move-wide/16 v10136, v20531
	move/16 v5181, v25703
	move/16 v5336, v11548
	move-wide/16 v3171, v213
	move/16 v6673, v26129
	move/16 v7557, v32092
	move/16 v22598, v2289
	move/16 v29937, v27869
	move-wide/16 v32092, v23309
	move/16 v32376, v29891
	move/16 v10621, v32238
	move-wide/16 v32196, v24195
	move-wide/16 v2896, v16352
	move/16 v19405, v8306
	move/16 v28934, v6661
	move/16 v31191, v20808
	move/16 v28317, v25994
	move/16 v13980, v4327
	move-wide/16 v24018, v20697
	move/16 v6714, v6661
	move-wide/16 v5732, v29725
	move/16 v6065, v13483
	move/16 v22084, v28723
	move-wide/16 v32061, v20711
	move-wide/16 v26096, v30752
	move-wide/16 v20792, v20697
	move/16 v5409, v26885
	move/16 v24877, v21975
	move-wide/16 v32093, v25028
	move/16 v18992, v11788
	move-wide/16 v31304, v16622
	move-wide/16 v24407, v32093
	move/16 v6850, v1108
	move/16 v20617, v1922
	move/16 v25846, v19673
	move/16 v13345, v12855
	move/16 v4668, v23130
	move/16 v13279, v19093
	move-wide/16 v15179, v1753
	move-wide/16 v30298, v12482
	move-wide/16 v23094, v2
	move/16 v4018, v928
	move/16 v7867, v13380
	move-wide/16 v13263, v176
	move-wide/16 v5496, v23207
	move/16 v19226, v14267
	move-wide/16 v31310, v23441
	move/16 v23105, v21367
	move-wide/16 v792, v8497
	move/16 v3765, v24718
	move/16 v15391, v23944
	move/16 v20763, v29684
	move/16 v18013, v19828
	move/16 v28882, v20202
	move/16 v6579, v8388
	move-wide/from16 v117, v3532
	move/16 v4018, v31441
	move-wide/16 v19490, v28254
	move/16 v16430, v4131
	move/16 v12425, v24397
	move-wide/16 v10188, v10464
	move/16 v1732, v17971
	move/16 v26161, v19226
	move-object/16 v6123, v1231
	move-wide/16 v14200, v16632
	move-wide/16 v20386, v26928
	move/16 v2262, v4804
	move-wide/16 v12425, v3138
	move-wide/16 v1127, v31982
	move/16 v22872, v32179
	move-wide/16 v792, v13305
	move-object/16 v17348, v12437
	move/16 v1756, v4568
	move/16 v6961, v16472
	move/16 v8522, v18462
	move-object/16 v10688, v19600
	move/16 v10135, v16891
	move/16 v15584, v21536
	move-wide/16 v25549, v26418
	move/16 v22019, v19899
	move/16 v17881, v21534
	move-object/16 v21655, v10210
	move/16 v812, v4001
	move/16 v15307, v21605
	move/16 v23548, v5924
	move-wide/16 v27192, v12147
	move/16 v28457, v30874
	move-wide/16 v18331, v4689
	move-wide/16 v27461, v21984
	move/16 v28911, v14862
	move/16 v17273, v3145
	move/16 v28622, v14912
	move-wide/16 v16552, v1109
	move-wide/16 v18819, v7062
	move/16 v18130, v16372
	move-object/16 v9106, v26741
	move-wide/16 v18463, v9164
	move-wide/16 v792, v27917
	move/16 v11406, v25499
	move/16 v12537, v26844
	move/16 v19750, v32048
	move-wide/16 v17555, v21755
	move-object/16 v13015, v28205
	move-wide/16 v18239, v13707
	move/16 v23880, v8817
	move/16 v3091, v12244
	move/16 v12539, v5629
	move/16 v19496, v32645
	move-wide/16 v12028, v5756
	move/16 v24773, v24772
	move-wide/16 v3419, v11079
	move-wide/16 v7977, v24950
	move/16 v7067, v28675
	move/16 v28143, v8186
	move-wide/16 v16428, v32117
	move-wide/16 v15149, v23592
	move/16 v9831, v18786
	move-wide/16 v32117, v21270
	move/16 v8391, v25263
	move-object/16 v26371, v9106
	move-object/16 v1141, v9806
	move/16 v31691, v29071
	move-object/16 v24230, v8602
	move-wide/16 v14267, v1673
	move-wide/16 v20868, v20782
	move-wide/16 v27344, v19417
	move-wide/16 v14, v21406
	move-object/16 v28767, v13544
	move-wide/16 v7435, v32730
	move-wide/16 v4548, v5376
	move-wide/16 v21968, v25924
	move-wide/16 v2638, v5760
	move-wide/16 v17679, v1397
	move/16 v7936, v6905
	move-wide/16 v18193, v10370
	move-wide/16 v9934, v7257
	move/16 v27360, v6719
	move/16 v18436, v10165
	move/16 v19357, v8037
	move-wide/16 v2705, v7440
	move/16 v22204, v10772
	move-object/16 v27261, v17876
	move/16 v6741, v32650
	move-wide/16 v29619, v2785
	move-wide/16 v29324, v1415
	move/16 v2862, v18027
	move/16 v28548, v4805
	move/16 v23073, v5473
	move/16 v27014, v585
	move-object/16 v16813, v24675
	move-wide/16 v17401, v14
	move-object/16 v23883, v32127
	move-wide/16 v2898, v3419
	move/16 v20808, v6291
	move/16 v14537, v11916
	move/16 v7620, v26563
	move/16 v14200, v24772
	move/16 v20863, v30517
	move/16 v27972, v22019
	move/16 v12965, v3413
	move/16 v15304, v8138
	move-wide/16 v9865, v18972
	move/16 v20622, v29249
	move/16 v21868, v7898
	move/16 v21344, v19453
	move-wide/16 v2248, v2695
	move-wide/16 v17060, v9455
	move-wide/16 v18240, v20314
	move/16 v11636, v14936
	move-wide/16 v548, v24587
	move/16 v28103, v10421
	move/16 v32428, v29727
	move/16 v26631, v31032
	move-object/16 v12626, v31691
	move/16 v2247, v23160
	move-object/16 v19312, v24589
	move-wide/16 v16691, v11438
	move/16 v5250, v18992
	move-wide/16 v16472, v23066
	move-wide/16 v15612, v792
	move-wide/16 v16196, v1556
	move-wide/16 v12004, v4062
	move-wide/16 v26418, v26127
	move-wide/16 v9601, v15745
	move-object/16 v16762, v32181
	move-wide/16 v31310, v19301
	move/16 v14827, v5354
	move/16 v22256, v16968
	move-object/16 v11335, v31286
	move-wide/16 v11438, v21559
	move-wide/16 v14267, v32093
	move/16 v25076, v18992
	move-wide/16 v15991, v16901
	move/16 v6973, v9167
	move-wide/16 v5629, v3622
	move/16 v24452, v9531
	move/16 v10376, v3049
	move/16 v26079, v31233
	move-wide/16 v31839, v22908
	move/16 v23584, v29287
	move/16 v2850, v14062
	move-wide/16 v6850, v3337
	move-object/16 v17216, v23312
	move-wide/16 v30594, v7172
	move/16 v12910, v0
	move-wide/16 v11064, v30652
	move-wide/16 v13029, v29725
	move-wide/16 v2785, v8233
	move-wide/16 v26161, v20314
	move-object/16 v2262, v19189
	move-object/16 v24514, v21344
	move-wide/16 v19600, v23788
	move/16 v15685, v9310
	move/16 v29725, v17608
	move/16 v1713, v5409
	move-wide/16 v8158, v24075
	move/16 v8264, v14493
	move-wide/16 v14586, v16901
	move/16 v11578, v5336
	move-object/16 v26536, v10684
	move-object/16 v7393, v13225
	move/16 v13808, v3087
	move-object/16 v23680, v1141
	move-wide/16 v30261, v17802
	move-object/16 v17839, v7772
	move-wide/16 v12745, v30009
	move-object/16 v2862, v12759
	move-wide/16 v13177, v16380
	move/16 v6039, v4031
	move-object/16 v30874, v32361
	move/16 v17216, v13281
	move/16 v18488, v14026
	move/16 v26549, v5908
	move-wide/16 v32016, v30535
	move/16 v27167, v3234
	move/16 v2809, v19365
	move-object/16 v29368, v24589
	move-wide/16 v7285, v6179
	move-wide/16 v3067, v24420
	move-wide/16 v8981, v16291
	move-wide/16 v10634, v21926
	move-wide/16 v9557, v3756
	move/16 v1743, v29736
	move/16 v8251, v8877
	move-wide/16 v30209, v21437
	move-object/16 v7393, v22764
	move/16 v11803, v2773
	move-wide/16 v1201, v13091
	move-wide/16 v27410, v3579
	move/16 v1029, v9360
	move-object/16 v14874, v22136
	move-wide/16 v11166, v872
	move/16 v20240, v30311
	move-object/16 v10388, v15983
	move/16 v11516, v8225
	move-wide/16 v11933, v21369
	move-wide/16 v9531, v14853
	move-wide/16 v2773, v27471
	move-object/16 v19263, v5588
	move-object/16 v9477, v31089
	move-object/16 v28275, v19904
	move-object/16 v18722, v18882
	move-wide/16 v26885, v7285
	move/16 v5391, v14936
	move-wide/16 v23812, v548
	move/16 v21989, v18348
	move-object/16 v16214, v58
	move/16 v8401, v28129
	move-wide/16 v5137, v5732
	move/16 v4819, v165
	move-wide/16 v19830, v5279
	move/16 v18013, v21536
	move-wide/16 v17135, v12302
	move/16 v29172, v10376
	move-object/16 v15161, v24486
	move-wide/16 v2687, v21119
	move-wide/16 v20069, v29017
	move/16 v17555, v31940
	move/16 v26457, v16871
	move-wide/16 v31598, v12506
	move-wide/16 v6208, v18986
	move/16 v16258, v29482
	move/16 v14272, v28317
	move-wide/16 v26893, v30981
	move-object/16 v32228, v24919
	move-wide/16 v28755, v25914
	move/16 v24038, v2610
	move-wide/16 v23337, v26069
	move/16 v4586, v27077
	move/16 v6653, v19323
	move-wide/16 v17383, v25880
	move/16 v3226, v5863
	move-wide/16 v2492, v24091
	move-wide/16 v1735, v339
	move/16 v29288, v31032
	move/16 v18330, v15849
	move-wide/16 v10721, v31185
	move-wide/16 v11597, v18968
	move-object/16 v785, v2900
	move-wide/16 v11960, v27376
	move-wide/16 v16038, v23425
	move/16 v31463, v23073
	move/16 v22084, v27717
	move/16 v2285, v26590
	move-object/16 v21899, v20153
	move/16 v2809, v16295
	move/16 v669, v10648
	move/16 v24788, v18511
	move-wide/16 v27376, v28811
	move-object/16 v1676, v24372
	move-wide/16 v16215, v5629
	move/16 v25713, v7169
	move/16 v17071, v14582
	move/16 v3138, v14841
	move-wide/16 v28640, v7073
	move-wide/16 v32348, v7443
	move-object/16 v9872, v11770
	move/16 v14806, v19541
	move-wide/16 v10221, v14535
	move/16 v18923, v13906
	move/16 v18013, v7105
	move/16 v22720, v4975
	move-object/16 v12937, v32253
	move-wide/16 v9552, v26715
	move/16 v8557, v22611
	move-wide/16 v22530, v7002
	move/16 v4915, v3202
	move-object/16 v19750, v16021
	move-wide/16 v10611, v8574
	move-wide/16 v14284, v16366
	move-wide/16 v3226, v7786
	move/16 v24486, v6973
	move-wide/16 v12275, v29940
	move/16 v18027, v1357
	move-object/16 v32688, v32391
	move/16 v26857, v14891
	move-object/16 v18486, v23494
	move-object/16 v11409, v4036
	move/16 v24031, v24291
	move-object/16 v16832, v9318
	move/16 v18879, v25957
	move-wide/16 v13282, v10219
	move-wide/16 v28401, v20697
	move-object/16 v331, v7628
	move/16 v7620, v10209
	move-object/16 v28648, v24802
	move-object/16 v30635, v21850
	move/16 v9966, v24486
	move-object/16 v15951, v19263
	move-wide/16 v32204, v14957
	move/16 v32208, v7593
	move/16 v13184, v19281
	move-wide/16 v9805, v17510
	move/16 v5698, v19989
	move/16 v5478, v13326
	move/16 v21968, v17608
	move/16 v8981, v15903
	move-object/16 v23862, v31499
	move/16 v15912, v26326
	move/16 v17107, v30576
	move/16 v30635, v18674
	move-object/16 v6511, v19825
	move/16 v27026, v21138
	move-object/16 v391, v16021
	move/16 v28469, v5635
	move-wide/16 v31085, v15366
	move/16 v16386, v29689
	move/16 v5616, v13164
	move-wide/16 v25251, v31419
	move-wide/16 v2811, v8158
	move/16 v20219, v17107
	move-wide/16 v28075, v26686
	move-object/16 v6439, v31691
	move-object/16 v32074, v24483
	move-wide/16 v22256, v6669
	move-object/16 v30268, v5635
	move/16 v5963, v6096
	move-wide/16 v26636, v19417
	move-wide/16 v23207, v30186
	move-wide/16 v1840, v28442
	move/16 v24081, v31463
	move/16 v13795, v11332
	move-object/16 v10491, v9066
	move/16 v8158, v4632
	move/16 v1415, v12001
	move-object/16 v12745, v28471
	move-wide/16 v6326, v7356
	move/16 v32007, v3946
	move-wide/16 v17667, v27274
	move/16 v10800, v1713
	move-object/16 v4055, v18079
	move/16 v12249, v3661
	move-wide/16 v31029, v4204
	move-wide/16 v18253, v4479
	move-wide/16 v10136, v28526
	move/16 v1411, v10390
	move/16 v11879, v7557
	move-wide/16 v6748, v1840
	move/16 v10468, v29710
	move-object/16 v2262, v19249
	move-object/16 v18094, v19249
	move-wide/16 v21677, v18077
	move/16 v2172, v28648
	move-wide/16 v8533, v27274
	move-object/16 v11879, v3500
	move-wide/16 v12285, v4019
	move/16 v19899, v29163
	move/16 v14537, v6257
	move/16 v30981, v29923
	move-wide/16 v18417, v18802
	move/16 v1102, v15292
	move-object/16 v14037, v3175
	move/16 v30498, v9249
	move-wide/16 v888, v29471
	move-wide/16 v19830, v5756
	move/16 v8685, v31696
	move-object/16 v26777, v1983
	move/16 v3330, v12761
	move-wide/16 v32225, v12715
	move-wide/16 v9310, v3579
	move/16 v9010, v22084
	move/16 v22307, v31955
	move-wide/16 v16472, v3430
	move/16 v17593, v476
	move/16 v25063, v29536
	move/16 v26350, v3099
	move-wide/16 v27983, v4432
	move-wide/16 v4307, v29940
	move/16 v26228, v29918
	move/16 v18946, v28143
	move/16 v27655, v27167
	move/16 v4077, v5140
	move-wide/16 v24106, v29381
	move-wide/16 v26353, v5528
	move/16 v32051, v7935
	move-wide/16 v10714, v28642
	move/16 v16273, v13328
	move-wide/16 v17911, v14466
	move-wide/16 v29725, v31910
	move-wide/16 v26798, v28578
	move-object/16 v9032, v3308
	move-object/16 v24031, v23052
	move-wide/16 v17095, v23968
	move-wide/16 v3353, v73
	move-wide/16 v21494, v12717
	move/16 v8233, v22526
	move/16 v12184, v20808
	move-wide/16 v23880, v16352
	move-object/16 v12348, v27464
	move/16 v10157, v16026
	move/16 v10874, v12554
	move-wide/16 v6010, v23670
	move/16 v24589, v8103
	move/16 v27807, v29276
	move/16 v31700, v17217
	move-object/16 v4290, v23862
	move-wide/16 v10135, v32260
	move/16 v2894, v32650
	move/16 v27344, v18168
	move-wide/16 v27436, v73
	move/16 v3337, v24333
	move/16 v26930, v1938
	move/16 v28181, v9060
	move-wide/16 v7620, v4815
	move/16 v8398, v10165
	move-wide/16 v8371, v23975
	move-object/16 v23511, v1960
	move/16 v25073, v1600
	move/16 v24357, v28332
	move-object/16 v11803, v19262
	move-wide/16 v10650, v23276
	move-wide/16 v29952, v7440
	move/16 v10817, v21534
	move-wide/16 v16769, v28871
	move-wide/16 v10737, v2811
	move-wide/16 v20838, v4150
	move-wide/16 v4001, v9552
	move-wide/16 v27217, v13726
	move-object/16 v10520, v5433
	move-wide/16 v8788, v5134
	move/16 v3820, v9959
	move/16 v342, v16947
	move-wide/16 v31475, v12689
	move-wide/16 v27167, v26353
	move-wide/16 v7172, v23660
	move-wide/16 v18472, v4736
	move-wide/16 v26129, v8788
	move/16 v20437, v31202
	move/16 v21981, v11588
	move-wide/16 v3019, v2683
	move/16 v3357, v11980
	move-wide/16 v29107, v16215
	move/16 v685, v14752
	move-wide/16 v17620, v2195
	move/16 v9250, v24383
	move-wide/16 v22948, v30864
	move/16 v23578, v24397
	move/16 v21215, v32418
	move/16 v15102, v11211
	move-wide/16 v8497, v5376
	move-wide/16 v4495, v20764
	move/16 v23238, v21822
	move/16 v6087, v19998
	move/16 v1396, v3783
	move-object/16 v4248, v21310
	move/16 v12164, v8883
	move-wide/16 v13888, v19411
	move-object/16 v6845, v32391
	move-object/16 v487, v1287
	move-wide/16 v30714, v25746
	move-wide/16 v8054, v5415
	move-wide/16 v1510, v17780
	move/16 v273, v10772
	move/16 v27655, v4819
	move/16 v6248, v16092
	move/16 v23066, v18013
	move/16 v25323, v20794
	move/16 v19411, v18774
	move-wide/16 v5616, v30738
	move/16 v1676, v3202
	move-wide/16 v21583, v24791
	move-wide/16 v9587, v12147
	move-wide/16 v17071, v3019
	move-wide/16 v21677, v22357
	move-wide/16 v24877, v15981
	move/16 v4975, v6738
	move/16 v18734, v23477
	move/16 v7797, v6752
	move/16 v1510, v1600
	move/16 v29530, v4805
	move/16 v4327, v11141
	move-wide/16 v4248, v7443
	move/16 v13579, v9322
	move/16 v17943, v24611
	move-object/16 v5246, v29144
	move/16 v2182, v31696
	move-object/16 v7532, v21868
	move-object/16 v27162, v23760
	move/16 v6037, v7680
	move-object/16 v28825, v13226
	move/16 v8587, v8209
	move/16 v24788, v18041
	move/16 v2064, v3078
	move/16 v13906, v9250
	move/16 v6179, v21806
	move/16 v15406, v8225
	move/16 v31281, v11458
	move/16 v12042, v29858
	move/16 v22574, v22392
	move/16 v13476, v22392
	move-object/16 v24499, v7772
	move/16 v23418, v3078
	move/16 v6881, v8897
	move/16 v15750, v617
	move-object/16 v19114, v27162
	move-object/16 v32373, v19189
	move/16 v5376, v32769
	move/16 v14284, v6515
	move-wide/16 v13990, v31155
	move-object/16 v8225, v21655
	move/16 v5215, v25135
	move-object/16 v19958, v21563
	move/16 v16832, v5261
	move-wide/16 v5522, v7858
	move/16 v3086, v22731
	move/16 v4031, v28094
	move/16 v20243, v25808
	move-object/16 v10012, v6584
	move-object/16 v16335, v2431
	move/16 v14841, v15414
	move-wide/16 v3918, v4495
	move-object/16 v16472, v10012
	move/16 v7628, v27101
	move/16 v28442, v14284
	move-object/16 v959, v23760
	move/16 v18118, v28267
	move-wide/16 v1732, v23026
	move/16 v2898, v11057
	move-wide/16 v10676, v31618
	move/16 v6037, v6291
	move/16 v9695, v25808
	move/16 v7449, v13452
	move/16 v21182, v19828
	move/16 v3296, v20617
	move/16 v22238, v17943
	move-object/16 v9644, v18630
	move-object/16 v30270, v28825
	move-wide/16 v22738, v3430
	move/16 v12467, v16092
	move/16 v23109, v9289
	move/16 v7073, v8388
	move/16 v8138, v23130
	move-object/16 v23616, v10958
	move/16 v19370, v20505
	move-wide/16 v16748, v2964
	move/16 v26226, v12855
	move/16 v26330, v132
	move-wide/16 v31869, v24669
	move-wide/16 v20931, v11628
	move/16 v31940, v21882
	move-object/16 v856, v10265
	move/16 v15361, v8557
	move/16 v31202, v22764
	move/16 v5114, v28622
	move/16 v21702, v29684
	move-object/16 v7557, v15925
	move-object/16 v30498, v7118
	move-wide/16 v27654, v30069
	move/16 v30105, v4029
	move-wide/16 v3349, v16932
	move-object/16 v16360, v31286
	move/16 v16170, v10380
	move-wide/16 v5250, v26273
	move/16 v13158, v19164
	move-wide/16 v28409, v30026
	move-wide/16 v30471, v17211
	move/16 v10520, v26732
	move-wide/16 v5042, v19550
	move/16 v26326, v8511
	move-object/16 v11775, v13226
	move-object/16 v4760, v7428
	move-object/16 v28590, v22773
	move-wide/16 v7963, v3238
	move-object/16 v22932, v26536
	move-object/16 v21488, v28205
	move/16 v29482, v7936
	move/16 v28882, v22776
	move-wide/16 v17538, v30307
	move/16 v13990, v17217
	move/16 v8353, v18734
	move-object/16 v5629, v7118
	move/16 v15849, v20247
	move-wide/16 v19884, v2835
	move/16 v10260, v27723
	move-wide/16 v19237, v4604
	move/16 v1960, v23781
	move-object/16 v17359, v17215
	move-object/16 v30026, v150
	move-object/16 v1769, v13693
	move-object/16 v31400, v22773
	move/16 v1840, v25073
	move-wide/16 v20711, v26885
	move-object/16 v8280, v10716
	move-wide/16 v31564, v27274
	move-object/16 v21119, v1769
	move/16 v1109, v24905
	move/16 v856, v30278
	move-object/16 v26096, v17839
	move-wide/16 v12282, v24193
	move-object/16 v24038, v16273
	move/16 v30594, v15469
	move-wide/16 v18374, v21437
	move/16 v2073, v13279
	move/16 v28143, v6577
	move/16 v15993, v30765
	move/16 v1800, v5924
	move-wide/16 v12700, v30728
	move-wide/16 v5473, v20123
	move/16 v15066, v5981
	move-wide/16 v25104, v17383
	move/16 v20243, v5963
	move/16 v16901, v3679
	move-wide/16 v32232, v6920
	move/16 v28296, v23830
	move-wide/16 v19453, v31910
	move/16 v8961, v2182
	move/16 v28469, v5863
	move/16 v6367, v25803
	move-wide/16 v14880, v3444
	move/16 v29750, v23584
	move-wide/16 v331, v32093
	move-wide/16 v14339, v30645
	move-wide/16 v3939, v16632
	move/16 v26516, v32428
	move/16 v5866, v24031
	move-wide/16 v4541, v13289
	move/16 v12001, v21119
	move/16 v17211, v19899
	move-wide/16 v2195, v794
	move-object/16 v28628, v26371
	move-wide/16 v31488, v25746
	move-wide/16 v16725, v29381
	move-wide/16 v21258, v29155
	move-wide/16 v27252, v14579
	move-object/16 v23511, v12222
	move-object/16 v21981, v27632
	move-wide/16 v20931, v21454
	move-wide/16 v7000, v10212
	move/16 v17060, v9283
	move-wide/16 v432, v1579
	move/16 v6879, v8557
	move/16 v22785, v1198
	move-wide/16 v27146, v5774
	move-object/16 v7056, v5246
	move/16 v16568, v32769
	move-object/16 v24912, v8225
	move/16 v23109, v3679
	move/16 v22445, v26954
	move-wide/16 v11928, v17095
	move/16 v31698, v15170
	move-object/16 v1638, v28129
	move-wide/16 v276, v14853
	move/16 v15378, v30765
	move-object/16 v15454, v22130
	move/16 v14877, v10800
	move/16 v24791, v13165
	move/16 v18036, v27671
	move-wide/16 v23050, v15201
	move/16 v7301, v8398
	move/16 v783, v14752
	move-wide/16 v20153, v16794
	move-wide/16 v12028, v2
	move-wide/16 v14633, v25008
	move/16 v32087, v26556
	move/16 v20202, v14537
	move/16 v20386, v17971
	move-object/16 v13865, v27787
	move/16 v23754, v26841
	move/16 v10962, v1908
	move/16 v9261, v21306
	move/16 v28060, v22168
	move-wide/16 v17802, v15443
	move-wide/16 v17802, v18819
	move/16 v18928, v15574
	move-wide/16 v24919, v6374
	move-wide/16 v20894, v26564
	move/16 v501, v17138
	move-wide/16 v20038, v13099
	move/16 v580, v32193
	move-object/16 v5134, v27366
	move/16 v26436, v31159
	move/16 v12282, v29276
	move/16 v19402, v6577
	move-wide/16 v16380, v26829
	move/16 v11397, v6087
	move/16 v7449, v812
	move-wide/16 v18118, v7435
	move/16 v13726, v5259
	move/16 v31742, v11548
	move-object/16 v24892, v836
	move-wide/16 v2136, v27436
	move/16 v2687, v14463
	move-wide/16 v1084, v30864
	move/16 v523, v10772
	move/16 v10176, v7935
	move/16 v27422, v16891
	move-wide/16 v18923, v18490
	move/16 v1981, v10482
	move/16 v20505, v2172
	move/16 v16192, v6757
	move/16 v9934, v22082
	move-object/16 v12184, v13784
	move-wide/16 v23872, v1973
	move-wide/16 v14874, v9601
	move/16 v7786, v1694
	move/16 v4651, v21552
	move-wide/16 v8481, v9403
	move-wide/16 v9132, v12147
	move-object/16 v24514, v9674
	move/16 v29961, v9384
	move-wide/16 v6511, v28609
	move/16 v176, v11775
	move-wide/16 v19141, v19914
	move/16 v31293, v6673
	move-object/16 v18348, v9872
	move/16 v24611, v15805
	move/16 v30250, v1381
	move/16 v2993, v15139
	move/16 v23686, v5372
	move/16 v9514, v25367
	move-object/16 v5086, v21342
	move/16 v10714, v21163
	move/16 v1556, v12698
	move/16 v19825, v27286
	move/16 v23830, v8200
	move-object/16 v26885, v11335
	move/16 v19858, v31748
	move-wide/16 v9039, v26923
	move/16 v6862, v24345
	move-object/16 v15446, v12611
	move-object/16 v2534, v24380
	move/16 v1688, v27026
	move/16 v32041, v20796
	move/16 v18226, v2850
	move-wide/16 v14062, v3303
	move/16 v6257, v3661
	move/16 v20714, v19828
	move-wide/16 v27654, v11933
	move/16 v3783, v22245
	move/16 v31004, v4319
	move-object/16 v31885, v29131
	move/16 v12510, v28713
	move-object/16 v29342, v32253
	move-wide/16 v30467, v8508
	move-object/16 v15406, v17593
	move-object/16 v7107, v7113
	move-wide/16 v28960, v2220
	move-wide/16 v5114, v21677
	move/16 v12506, v16891
	move-object/16 v27787, v11634
	move-wide/16 v27742, v22738
	move-wide/16 v25598, v3720
	move-wide/16 v19652, v18972
	move/16 v14339, v2031
	move-wide/16 v18819, v2773
	move/16 v3091, v4915
	move-object/16 v26050, v5086
	move/16 v24327, v21702
	move/16 v2479, v5963
	move/16 v5760, v21367
	move/16 v12119, v21481
	move/16 v27066, v2060
	move-wide/16 v31337, v22738
	move-wide/16 v17853, v17095
	move-wide/16 v16352, v20308
	move-wide/16 v28759, v16769
	move-wide/16 v11812, v12501
	move/16 v26732, v5282
	move-wide/16 v8225, v22357
	move-wide/16 v3091, v16941
	move/16 v2898, v29961
	move/16 v16518, v617
	move/16 v23050, v6277
	move/16 v30714, v6741
	move-wide/16 v4828, v1127
	move-wide/16 v27252, v6326
	move/16 v15378, v8158
	move/16 v3067, v9966
	move/16 v30635, v4327
	move/16 v16622, v11397
	move-wide/16 v28734, v23276
	move/16 v2610, v27026
	move/16 v12155, v15271
	move-object/16 v22779, v23092
	move/16 v29360, v5331
	move-wide/16 v17896, v25924
	move-object/16 v2900, v25713
	move-wide/16 v17633, v30838
	move/16 v1732, v26422
	move-object/16 v19541, v24824
	move/16 v11960, v28103
	move-object/16 v23337, v14005
	move-wide/16 v28449, v4495
	move/16 v7056, v16048
	move/16 v31845, v12506
	move-wide/16 v14936, v27654
	move/16 v11788, v16901
	move/16 v25686, v19699
	move/16 v16129, v31408
	move-wide/16 v5774, v15991
	move/16 v8057, v14177
	move-wide/16 v9066, v9197
	move-object/16 v20333, v15066
	move/16 v20067, v19974
	move-object/16 v32117, v16654
	move/16 v22731, v1638
	move/16 v14616, v12554
	move/16 v8200, v26472
	move-wide/16 v32149, v24075
	move-object/16 v27376, v26057
	move-object/16 v26079, v12184
	move/16 v23968, v2862
	move/16 v9310, v6881
	move-wide/16 v5774, v597
	move/16 v4524, v26590
	move-wide/16 v30232, v27584
	move-wide/16 v6805, v3171
	move-wide/16 v15489, v28586
	move-object/16 v19989, v19402
	move/16 v488, v4018
	move/16 v19323, v21919
	move-wide/16 v6245, v26829
	move/16 v23511, v13380
	move/from16 v94, v21344
	move-wide/16 v29400, v4561
	move-object/16 v19301, v23874
	move-wide/16 v4943, v3072
	move/16 v22299, v12966
	move-wide/16 v14659, v8460
	move/16 v31275, v24247
	move-object/16 v2104, v9208
	move-wide/16 v3064, v9066
	move-object/16 v8031, v19263
	move-wide/16 v31310, v12343
	move/16 v17780, v9751
	move-object/16 v16258, v12971
	move/16 v2220, v32028
	move-wide/16 v2610, v1735
	move/16 v14037, v25063
	move-wide/16 v2295, v9552
	move-object/16 v32048, v1638
	move-wide/16 v28911, v30227
	move-wide/16 v8475, v2705
	move-wide/16 v30594, v32232
	move/16 v27697, v14912
	move-object/16 v22523, v8474
	move/16 v13345, v5976
	move/16 v2773, v11445
	move-wide/16 v24939, v16941
	move/16 v16401, v20247
	move-wide/16 v8925, v7002
	move-wide/16 v18131, v11832
	move-wide/16 v19559, v24955
	move-wide/16 v6305, v25924
	move-wide/16 v21882, v17714
	move-wide/16 v29765, v671
	move-object/16 v213, v12437
	move-wide/16 v31691, v14927
	move/16 v28664, v22562
	move-wide/16 v26203, v5959
	move/16 v32632, v28386
	move-object/16 v3337, v26113
	move/16 v11793, v5908
	move-object/16 v24383, v21426
	move-wide/16 v19453, v29619
	move-object/16 v22530, v2883
	move-object/16 v10491, v16167
	move-wide/16 v31807, v11782
	move/16 v27907, v21919
	move/16 v25008, v22208
	move/16 v18170, v6298
	move-wide/16 v29541, v4925
	move-wide/16 v8103, v31439
	move/16 v19830, v30727
	move-wide/16 v9966, v10721
	move-wide/16 v32418, v11554
	move/16 v3651, v6653
	move-wide/16 v29589, v2497
	move/16 v441, v31275
	move/16 v25104, v6783
	move-wide/16 v8037, v12557
	move-object/16 v25887, v4077
	move/16 v29079, v28594
	move/16 v24166, v18013
	move/16 v28723, v13579
	move-wide/16 v16428, v17786
	move/16 v20894, v5924
	move/16 v17475, v32074
	move-object/16 v18041, v18999
	move/16 v634, v7281
	move/16 v29536, v32428
	move/16 v2220, v26590
	move/16 v29163, v8388
	move-object/16 v342, v26885
	move-wide/16 v9283, v9358
	move/16 v9098, v9271
	move/16 v2228, v6738
	move/16 v23812, v9027
	move-object/16 v28547, v22293
	move-wide/16 v792, v10732
	move/16 v4495, v19048
	move-object/16 v20889, v25831
	move/16 v23511, v8981
	move/16 v29725, v24247
	move/16 v15149, v11793
	move-wide/16 v12001, v21437
	move/16 v8817, v13483
	move/16 v9353, v25994
	move/16 v13029, v17780
	move-object/16 v1960, v9639
	move-wide/16 v12004, v32239
	move/16 v23094, v24397
	move/16 v32604, v756
	move/16 v24733, v4855
	move/16 v13177, v13508
	move-wide/16 v30503, v9907
	move-wide/16 v14579, v18481
	move-wide/16 v2132, v12425
	move-wide/16 v12119, v56
	move/16 v32333, v8994
	move/16 v31159, v29563
	move-wide/16 v10380, v11020
	move-wide/16 v20794, v30471
	move/16 v31004, v18419
	move-object/16 v1637, v28466
	move/16 v32688, v15271
	move-wide/16 v24499, v26669
	move-wide/16 v3726, v1054
	move-wide/16 v17369, v2495
	move-wide/16 v29381, v27917
	move-wide/16 v28778, v20034
	move-object/16 v501, v15925
	move-object/16 v4689, v9477
	move-wide/16 v19481, v29155
	move-wide/16 v7449, v15166
	move-wide/16 v6862, v27983
	move-object/16 v5279, v21342
	move-wide/16 v20794, v2705
	move/16 v20992, v30765
	move/16 v15198, v27639
	move/16 v16739, v1306
	move/16 v31295, v32333
	move-wide/16 v24788, v20838
	move-object/16 v17475, v21119
	move/16 v3192, v31463
	move-wide/16 v12501, v14586
	move-wide/16 v12557, v3918
	move/16 v28085, v7073
	move-wide/16 v8398, v17401
	move/16 v28948, v3009
	move-wide/16 v18645, v20274
	move/16 v14065, v8306
	move/16 v12614, v13944
	move-wide/16 v4661, v3226
	move/16 v24977, v18462
	move-wide/16 v19014, v12478
	move/16 v3444, v27066
	move/16 v29324, v15925
	move/16 v3890, v6752
	move/16 v26270, v17971
	move/16 v2683, v28094
	move/16 v691, v15574
	move-wide/16 v17273, v9197
	move-wide/16 v12190, v6028
	move-wide/16 v28622, v18342
	move-object/16 v4319, v31499
	move/16 v13601, v23618
	move/16 v14055, v9639
	move/16 v22293, v30833
	move/16 v18674, v5737
	move-object/16 v6581, v2534
	move/16 v6123, v19102
	move-wide/16 v5541, v2896
	move/16 v26418, v14952
	move/16 v3651, v27639
	move-wide/16 v7169, v18819
	move-wide/16 v27382, v5429
	move-wide/16 v12437, v19914
	move-object/16 v14616, v11879
	move-wide/16 v32087, v20418
	move-wide/16 v30742, v6862
	move-wide/16 v25057, v8497
	move-wide/16 v30356, v8475
	move-wide/16 v16901, v2896
	move-wide/16 v16691, v25251
	move/16 v27713, v15102
	move-wide/16 v5374, v28075
	move-wide/16 v8303, v6862
	move-wide/16 v29704, v7440
	move-object/16 v15761, v32363
	move/16 v5982, v6896
	move/16 v23781, v13808
	move/16 v14652, v24977
	move-wide/16 v22459, v24018
	move/16 v32547, v20067
	move-wide/16 v6757, v30290
	move/16 v15235, v14200
	move-wide/16 v13808, v24877
	move/16 v27146, v13279
	move/16 v14213, v2809
	move/16 v29536, v7385
	move-wide/16 v24081, v17802
	move-wide/16 v2483, v12715
	move/16 v21488, v1342
	move/16 v5866, v18992
	move-wide/16 v24128, v162
	move-wide/16 v2093, v27461
	move-wide/16 v18417, v29952
	move/16 v18464, v3840
	move/16 v23094, v31731
	move/16 v23144, v9027
	move/16 v13099, v3357
	move-wide/16 v27997, v8167
	move/16 v23238, v32074
	move/16 v18819, v16649
	move/16 v20466, v21573
	move-object/16 v25994, v28205
	move/16 v22682, v22574
	move-wide/16 v21276, v16552
	move-wide/16 v17169, v16461
	move-wide/16 v11928, v21904
	move-object/16 v15375, v11775
	move-wide/16 v559, v17273
	move-wide/16 v30965, v29713
	move-object/16 v6768, v4290
	move/16 v20067, v8256
	move/16 v4723, v29961
	move/16 v18641, v31955
	move/16 v10380, v31679
	move-wide/16 v10932, v9966
	move-wide/16 v1600, v21369
	move/16 v32179, v13476
	move-wide/16 v2228, v25251
	move-object/16 v1938, v23185
	move-wide/16 v14387, v7440
	move/16 v4750, v11900
	move/16 v8994, v31233
	move/16 v32449, v23678
	move/16 v10517, v8256
	move/16 v20448, v26350
	move-wide/16 v8699, v26365
	move/16 v21893, v3917
	move/16 v12921, v10116
	move/16 v22299, v22293
	move-object/16 v25746, v3764
	move/16 v24372, v7067
	move-wide/16 v12518, v2907
	move-wide/16 v30759, v3585
	move-wide/16 v12910, v19417
	move/16 v31748, v8209
	move/16 v30325, v6515
	move-object/16 v30783, v17475
	move-object/16 v6879, v27632
	move-wide/16 v29187, v30738
	move/16 v26436, v617
	move/16 v7534, v17217
	move-object/16 v2295, v15960
	move/16 v32127, v23548
	move-wide/16 v26127, v4001
	move-object/16 v7238, v25887
	move/16 v10645, v6905
	move-object/16 v8270, v24380
	move-object/16 v19321, v9644
	move-object/16 v4260, v15951
	move-object/16 v12614, v18630
	move/16 v22182, v2800
	move/16 v8481, v25482
	move/16 v24925, v29961
	move/16 v11258, v26373
	move-wide/16 v15744, v33
	move-wide/16 v5558, v31185
	move-wide/16 v24114, v18172
	move-wide/16 v10666, v10721
	move/16 v9457, v11916
	move/16 v8915, v22526
	move/16 v12025, v11660
	move/16 v21175, v6300
	move-wide/16 v9834, v604
	move-wide/16 v19779, v16769
	move-wide/16 v11534, v28642
	move-wide/16 v27356, v16380
	move/16 v3858, v29858
	move/16 v21612, v8320
	move/16 v22068, v16968
	move/16 v3938, v22682
	move/16 v170, v7628
	move-object/16 v23847, v27376
	move/16 v3949, v20103
	move/16 v29086, v6690
	move/16 v1380, v31698
	move/16 v23316, v24232
	move/16 v4370, v21668
	move/16 v18755, v9010
	move-wide/16 v11262, v1971
	move-wide/16 v10041, v26636
	move-wide/16 v23357, v8925
	move-wide/16 v28025, v18539
    ############################################################################

    const v0, 0x2c0e
    move/16 v1, v12025
    if-eq v1, v0, :else

    invoke-static/range {v8270}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static/range {v22182}, LL/util;->print(I)V
    invoke-static/range {v15744..v15745}, LL/util;->print(D)V
    invoke-static/range {v9457}, LL/util;->print(I)V
    invoke-static/range {v9834..v9835}, LL/util;->print(J)V
    invoke-static/range {v3858}, LL/util;->print(F)V
    invoke-static/range {v170}, LL/util;->print(Ljava/lang/Object;)V

    invoke-static/range {v23847}, LL/util;->print(I)V
    invoke-static/range {v1380}, LL/util;->print(I)V
    invoke-static/range {v11262..v11263}, LL/util;->print(J)V
    return-void
:else
    invoke-static/range {v19321}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static/range {v8481}, LL/util;->print(I)V
    invoke-static/range {v5558..v5559}, LL/util;->print(D)V
    invoke-static/range {v8915}, LL/util;->print(I)V
    invoke-static/range {v19779..v19780}, LL/util;->print(J)V
    invoke-static/range {v21612}, LL/util;->print(F)V
    invoke-static/range {v3949}, LL/util;->print(Ljava/lang/Object;)V

    invoke-static/range {v29086}, LL/util;->print(F)V
    invoke-static/range {v23316}, LL/util;->print(F)V
    invoke-static/range {v10041..v10042}, LL/util;->print(D)V
    return-void
.end method

.method testMoves()V
    .locals 22
    const-string v0, "testMoves"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V

    move-object/from16 v0, p0
    const v1, 0x15ADE1AA
    const-wide v2, 0x6366736AB654F93CL
    const v4, 0x2C0E
    const-wide v5, 0x11BDFC4CAF473799L
    const v7, 0xCB7D567A
    invoke-interface/range {v0..v7}, L_;->testMovesSub(IDCJF)V

    const v1, 0xCF5E720B
    const-wide v2, 0xE5E5F7123B414FBEL
    const v4, 0x1924
    const-wide v5, 0xCF70DF71BAA07C71L
    const v7, 0xDF98CCC6
    invoke-interface/range {v0..v7}, L_;->testMovesSub(IDCJF)V

    return-void
.end method

.field static Code:F = 123.456f
.field static F:I = 654.321f

.method private static testCatchAllSub(I[I[I)V
	.locals 2
	move v1, p0

	sget v0, La/a;->Code:F
	invoke-static {v0}, LL/util;->print(F)V
	sget v0, La/a;->F:I
	invoke-static {v0}, LL/util;->print(I)V

:start
	array-length v0, p1
	sput v1, La/a;->F:I

:holestart
	sget v1, La/a;->Code:F
	const v0, -0.000177f
	sub-float/2addr v1, v0
	sput v1, La/a;->Code:F

	sget v1, La/a;->F:I
:holeend
	xor-int/2addr v1, v0
	check-cast p2, [F
	invoke-static {p2}, LL/util;->print(Ljava/lang/Object;)V
	fill-array-data p2, :array_data
	return-void
	goto :outer_handler
:end

.catch Ljava/lang/Throwable; {:holestart .. :holeend} :inner_handler
.catchall {:holestart .. :holeend} :inner_handler
.catchall {:start .. :end} :outer_handler

:inner_handler
    move-exception p0
    invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V
    return-void

:outer_handler
    move-exception p0
	invoke-static {v1}, LL/util;->print(I)V
    invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V
    return-void

:array_data
    .array-data 4
    	42
    .end array-data
.end method

.method private static testCatchAll(L_;)V
    .locals 22
    const-string v0, "testCatchAll"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V

    const v0, 0x15ADE1AA
    const v1, 0
    new-array v2, v1, [I

    invoke-static {v0, v1, v1}, La/a;->testCatchAllSub(I[I[I)V
    const v0, 0x15ADE1AA
    invoke-static {v0, v1, v2}, La/a;->testCatchAllSub(I[I[I)V
    const v0, 0x47B9D09C
    invoke-static {v0, v2, v2}, La/a;->testCatchAllSub(I[I[I)V
    const v0, 0x4AD8F486
    invoke-static {v0, v2, v1}, La/a;->testCatchAllSub(I[I[I)V
    return-void
.end method

.method static testMonitorSubSubA(Ljava/lang/Object;BB)V
    .locals 2

    const v0, 256
    mul-int/2addr v0, p1
    add-int/2addr v0, p2
    invoke-static {v0}, LL/util;->print(I)V

    if-eqz p2, :else2
    	const-string v0, "entering monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-enter p0
	    #goto :end2
	:else2
    	const-string v0, "entering monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-enter p0
	:end2

	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V

	const-string v0, "exiting monitor"
	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    monitor-exit p0

    return-void
.end method

.method static testMonitorSubSubB(Ljava/lang/Object;BB)V
    .locals 2

:start
    const v0, 256
    mul-int/2addr v0, p1
    add-int/2addr v0, p2
    invoke-static {v0}, LL/util;->print(I)V

	const-string v0, "entering monitor"
	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

    monitor-enter p0

	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V

    if-eqz p1, :else1
    	const-string v0, "exiting monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-exit p0
	    #goto :end1
	:else1
    	const-string v0, "exiting monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-exit p0
	:end1

    return-void
:end
.catchall {:start .. :end} :handler
:handler
    move-exception p0
    invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V
    return-void

.end method

# WTF?
.method static testMonitorSubSubAB(Ljava/lang/Object;BB)V
    .locals 2


    const v0, 256
    mul-int/2addr v0, p1
    add-int/2addr v0, p2
    invoke-static {v0}, LL/util;->print(I)V

    if-eqz p2, :else2
    	const-string v0, "entering monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-enter p0
	    #goto :end2
	:else2
    	const-string v0, "entering monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-enter p0
	:end2

	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V


    if-eqz p1, :else1
    	const-string v0, "exiting monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-exit p0
	    #goto :end1
	:else1
    	const-string v0, "exiting monitor"
    	invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

	    monitor-exit p0
	:end1

    return-void


.end method

.method static testMonitorSub(Ljava/lang/Object;BB)V
    .locals 0

:start
    invoke-static {p0, p1, p2}, La/a;->testMonitorSubSubB(Ljava/lang/Object;BB)V
:end
    return-void

# .catchall {:start .. :end} :handler
:handler
    move-exception p0
    invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V
    return-void
.end method

.method static testMonitor(L_;)V
    .locals 3
    const-string v0, "testMonitor"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V
    const-string v0, "Inside the monitors"

    const/4 v1, 0
    const/4 v2, 1
    invoke-static {v0, v1, v1}, La/a;->testMonitorSub(Ljava/lang/Object;BB)V
    invoke-static {v0, v1, v2}, La/a;->testMonitorSub(Ljava/lang/Object;BB)V
    invoke-static {v0, v2, v2}, La/a;->testMonitorSub(Ljava/lang/Object;BB)V
    invoke-static {v0, v2, v1}, La/a;->testMonitorSub(Ljava/lang/Object;BB)V

    return-void
.end method

.method static testCasts()V
    .locals 3
    const-string v0, "testCasts"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V

    const v0, 0
    instance-of v0, v0, [I
	invoke-static {v0}, LL/util;->print(I)V

	new-instance v0, Ljava/util/Stack;
	invoke-direct {v0}, Ljava/util/Stack;-><init>()V

:start
	#check-cast v0, Ljava/util/Vector;
	instance-of v1, v0, Ljava/util/Vector;
	if-eqz v1, :bad


	invoke-virtual {v0}, Ljava/util/Stack;->empty()Z
	move-result v1
	invoke-static {v1}, LL/util;->print(I)V

	#check-cast v0, Ljava/lang/Object;
	instance-of v1, v0, Ljava/lang/Object;
	if-eqz v1, :bad

	invoke-virtual {v0, v0}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

	#check-cast v0, Ljava/util/AbstractCollection;
	instance-of v1, v0, Ljava/util/AbstractCollection;
	if-eqz v1, :bad

	invoke-virtual {v0}, Ljava/util/Stack;->empty()Z
	move-result v1
	invoke-static {v1}, LL/util;->print(I)V

	check-cast v0, Ljava/lang/String;
	check-cast v0, Ljava/util/Stack;

	invoke-virtual {v0}, Ljava/util/Stack;->empty()Z
	move-result v1
	invoke-static {v1}, LL/util;->print(I)V
    return-void

:bad
.catch Ljava/lang/RuntimeException; {:start .. :bad} :bad
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V
    return-void

.end method

.field public static _:L_;
.method static testInterfaceAssign(L_;)V
    .locals 2
    move-object v0, p0
:start
    instance-of v1, v0, L_;
    invoke-static {v1}, LL/util;->print(I)V
    check-cast v0, L_;

    sput-object v0, La/a;->_:L_;
    sget-object v0, La/a;->_:L_;

    instance-of v1, v0, L_;
    invoke-static {v1}, LL/util;->print(I)V

    check-cast v0, L_;
    return-void
:bad
.catch Ljava/lang/RuntimeException; {:start .. :bad} :bad
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    move-result-object v0
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V
    return-void

.end method

.method static testImplicitCastsThrow(Ljava/lang/Object;)V
	.locals 2
	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V

	move-object v0, p0
	instance-of v1, v0, Ljava/lang/Exception;
	if-eqz v1, :end
	throw p0

	:end
	return-void
.end method

.method static testImplicitCastsArrayLen(Ljava/lang/Object;)[I
	.locals 3
	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V

	const v2, 0
	move-object v0, p0
	instance-of v1, v0, [[F
	if-eqz v1, :elif

	goto :merge
:elif
	instance-of v1, v0, [[I
	if-eqz v1, :end

	aget-object v2, v0, v1

	goto :merge
:end
	return-object v2
:merge
	array-length v1, v0
	goto :end
.end method

.method static testImplicitCastsArrayGet(Ljava/lang/Object;)D
	.locals 1
	invoke-static {p0}, LL/util;->print(Ljava/lang/Object;)V
	move-object p0, p0

	instance-of v0, p0, [[[D
	if-nez v0, :arr3

	instance-of v0, p0, [[D
	if-nez v0, :arr2

	instance-of v0, p0, [D
	if-nez v0, :arr1

	const-wide v0, 077.770
	return-wide v0

:arr3
	aget-object p0, p0, v0
:arr2
	aget-object p0, p0, v0
:arr1
	aget-wide v0, p0, v0
	return-wide v0
.end method

.method static testImplicitCastsArrayStore(Ljava/lang/Object;)V
	.locals 3

	instance-of v0, p0, [D
	if-eqz v0, :notD

	const v0, 1
	const-wide v1, -111.0
	aput-wide v1, p0, v0

	const v0, 2
	const-wide v1, -31.111
	aput-wide v1, p0, v0

	const v0, 3
	const-wide v1, -1311.31
	aput-wide v1, p0, v0

	const v0, 4
	const-wide v1, -111321.1311
	aput-wide v1, p0, v0

	const v0, 5
	const-wide v1, -31131211.1311
	aput-wide v1, p0, v0
	return-void

:notD
	instance-of v1, p0, [I
	if-eqz v1, :notI

	array-length v1, p0
	aput v1, p0, v0

:notI
	return-void
.end method

.method static testImplicitCasts()V
    .locals 7
    const-string v0, "testImplicitCasts"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V

    #invoke-static {v0}, La/a;->testInterfaceAssign(L_;)V

    const-string v0, "whatever"
    sput-object v0, La/a;->_:L_;
    sget-object v0, La/a;->_:L_;
    #check-cast v0, L_;

	new-instance v1, Ljava/lang/Throwable;
	invoke-direct {v1}, Ljava/lang/Throwable;-><init>()V
	new-instance v2, Ljava/lang/ArrayStoreException;
	invoke-direct {v2}, Ljava/lang/ArrayStoreException;-><init>()V

:start1
	invoke-static {v0}, La/a;->testImplicitCastsThrow(Ljava/lang/Object;)V

	const v0, 0
	invoke-static {v0}, La/a;->testImplicitCastsThrow(Ljava/lang/Object;)V

	move-object v0, v1
	invoke-static {v0}, La/a;->testImplicitCastsThrow(Ljava/lang/Object;)V

	move-object v0, v2
	invoke-static {v0}, La/a;->testImplicitCastsThrow(Ljava/lang/Object;)V
	goto :end1

:handler1
.catch Ljava/lang/RuntimeException; {:start1 .. :end1} :handler1
    move-exception v0
    const-string v1, "catch1"
    invoke-static {v1}, LL/util;->print(Ljava/lang/Object;)V
    invoke-static {v0}, LL/util;->print(Ljava/lang/Object;)V

:end1

	const v0, 6
	new-array v1, v0, [D
	new-array v0, v0, [D
	fill-array-data v0, :array_data1
	fill-array-data v1, :array_data2

	filled-new-array {v0, v1}, [[D
	move-result-object v2

	const v3, 0
	filled-new-array {v2, v2, v3}, [[[D
	move-result-object v4

	const-string v5, "whatever"

	invoke-static {v5}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	invoke-static {v4}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	invoke-static {v3}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	invoke-static {v2}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	invoke-static {v1}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	invoke-static {v0}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	const v0, 0
	invoke-static {v0}, La/a;->testImplicitCastsArrayGet(Ljava/lang/Object;)D
	move-result-wide v5
	invoke-static {v5, v6}, LL/util;->print(D)V

	# array store tests
:array_store_tests
	const-string v2, "whatever"
	const/16 v0, 14
	new-array v0, v0, [I

	filled-new-array/range {v0 .. v4}, [Ljava/lang/Object;
	#filled-new-array/range {v0 .. v4}, [Ljava/lang/Cloneable;
	move-result-object v4

	invoke-static {v4}, LL/util;->print(Ljava/lang/Object;)V
	invoke-static {v0}, La/a;->testImplicitCastsArrayStore(Ljava/lang/Object;)V
	invoke-static {v1}, La/a;->testImplicitCastsArrayStore(Ljava/lang/Object;)V
	invoke-static {v2}, La/a;->testImplicitCastsArrayStore(Ljava/lang/Object;)V
	invoke-static {v3}, La/a;->testImplicitCastsArrayStore(Ljava/lang/Object;)V
	invoke-static {v4}, La/a;->testImplicitCastsArrayStore(Ljava/lang/Object;)V
	invoke-static {v4}, LL/util;->print(Ljava/lang/Object;)V

    return-void

:array_data1
    .array-data 8
        3.0f 234.3f -0.0f NaNf 0.5f 17e17f
    .end array-data
:array_data2
    .array-data 8
        3.0 234.3 -0.0 NaN 0.5 17e17
    .end array-data
.end method

.method static testMathOpsSub(IIIFFFJJJDDDJ)V
    .locals 257
################################################################################
	move/from16 v0, v257
	move/from16 v1, v258
	move/from16 v2, v259
	move/from16 v3, v260
	move/from16 v4, v261
	move/from16 v5, v262
	move-wide/from16 v6, v263
	move-wide/from16 v8, v265
	move-wide/from16 v10, v267
	move-wide/from16 v12, v269
	move-wide/from16 v14, v271
	move-wide/from16 v16, v273
	neg-int v9, v0
	or-int/2addr v1, v0
	ushr-long v41, v6, v9
	ushr-int/2addr v1, v9
	div-float v48, v5, v4
	double-to-long v11, v12
	sub-int/2addr v1, v0
	double-to-float v12, v14
	const-wide v5, 0x66ecddd7b744941bL
	mul-double/2addr v14, v5
	xor-int/2addr v9, v0
	add-int/2addr v0, v2
	not-int v13, v0
	or-int/lit8 v1, v1, 88
	rem-int/2addr v2, v1
	const-wide v14, 0x8c496118632b349fL
	const-wide v8, 0xcb10debd41798c83L
	or-long/2addr v14, v8
	float-to-int v5, v3
	int-to-double v8, v5
	int-to-float v2, v13
	const-wide v13, 0xf792872ab0029e39L
	mul-double/2addr v8, v13
	or-int/lit8 v1, v1, 100
	div-int v157, v0, v1
	sub-int v50, v1, v157
	mul-float v30, v12, v3
	const-wide v6, 0xee4219ed7f5f9befL
	const-wide v3, 0xef9225f8cac68140L
	sub-long/2addr v6, v3
	shr-int/2addr v1, v0
	int-to-long v12, v0
	add-long/2addr v3, v12
	or-int/lit8 v110, v157, -101
	mul-float v254, v48, v30
	const-wide v6, 262144L
	or-long v6, v6, v6
	div-long v222, v41, v6
	shl-int/lit8 v192, v50, -28
	neg-float v2, v2
	add-float v189, v254, v30
	shr-long v251, v41, v157
	shl-int v41, v110, v50
	rsub-int v15, v0, -30873
	shr-int/2addr v5, v1
	or-int/lit8 v41, v41, 52
	rem-int v245, v192, v41
	add-int/2addr v5, v15
	const v11, 0xf4e6663a
	mul-float/2addr v2, v11
	sub-double v45, v16, v8
	xor-int/lit8 v151, v192, -126
	shr-int/2addr v1, v15
	int-to-char v2, v5
	neg-long v6, v6
	or-int/lit8 v50, v50, 8
	div-int v87, v5, v50
	int-to-char v15, v15
	or-long v90, v222, v251
	xor-long v3, v251, v3
	long-to-double v5, v3
	mul-int/lit8 v206, v151, -13
	int-to-long v10, v15
	const v7, 0xdde29dc6
	const v5, 0x505daf85
	rem-float/2addr v5, v7
	neg-float v12, v5
	float-to-int v6, v12
	xor-int/2addr v6, v2
	xor-int/2addr v0, v1
	rem-int/lit16 v15, v1, 15472
	xor-int/lit16 v15, v15, 22391
	shl-int/2addr v15, v2
	xor-int/2addr v2, v6
	int-to-short v1, v6
	const-wide v10, 524288L
	or-long v10, v10, v10
	div-long/2addr v3, v10
	rem-float/2addr v5, v7
	const-wide v5, 0xc9aafeeb0abbb858L
	mul-double/2addr v5, v8
	not-long v1, v3
	shl-int/lit8 v173, v157, -104
	add-long v105, v10, v1
	float-to-double v9, v12
	and-int/lit8 v88, v0, 70
	or-int v77, v88, v50
	ushr-int v61, v173, v110
	or-int/lit16 v4, v0, 15454
	add-float/2addr v12, v7
	xor-long v97, v1, v90
	ushr-int v200, v206, v173
	add-double v230, v45, v16
	shl-int/2addr v0, v15
	shr-long v155, v1, v50
	mul-long v155, v1, v105
	sub-double/2addr v5, v9
	sub-float v79, v7, v12
	rsub-int/lit8 v152, v88, 102
	sub-float v58, v79, v12
	shr-long/2addr v1, v4
	add-int/lit16 v11, v0, 6196
	neg-double v3, v9
	div-float v229, v7, v30
	shr-int/lit8 v43, v151, 56
	const-wide v11, 0x9231367497e82e53L
	const-wide v222, 128L
	or-long v11, v11, v222
	div-long/2addr v1, v11
	div-double/2addr v5, v9
	shl-int/lit8 v116, v41, 58
	xor-int v28, v88, v0
	rsub-int/lit8 v91, v41, 101
	int-to-float v10, v0
	and-int v30, v88, v77
	mul-long v1, v1, v11
	mul-int/lit16 v8, v15, 1260
	and-int v42, v116, v152
	mul-float v157, v10, v229
	ushr-int/2addr v0, v15
	and-int v227, v192, v50
	sub-long v3, v251, v1
	add-float/2addr v7, v10
	or-long/2addr v11, v1
	const-wide v15, 0x93cb72485b399c3dL
	add-double/2addr v5, v15
	xor-int v246, v88, v77
	int-to-double v0, v8
	sub-float v169, v58, v79
	sub-float v63, v79, v169
	long-to-float v5, v11
	sub-int v68, v87, v42
	float-to-double v5, v5
	const v8, 0xde1fa753
	const v7, 0x94654e00
	or-int/lit8 v8, v8, 126
	div-int/2addr v7, v8
	add-double v244, v5, v230
	sub-double v15, v230, v15
	and-int/2addr v7, v8
	shl-long v55, v251, v8
	sub-double v32, v5, v15
	or-int/lit8 v116, v116, 82
	rem-int v38, v200, v116
	and-long/2addr v11, v3
	shr-int/2addr v8, v7
	xor-int v6, v43, v61
	sub-double v30, v0, v45
	shl-long/2addr v11, v7
	double-to-float v11, v0
	div-double v68, v15, v32
	float-to-int v8, v11
	long-to-int v14, v3
	add-int/2addr v8, v6
	mul-int/lit16 v10, v8, -1802
	long-to-double v11, v3
	const-wide v4, 0x93f3b9e31689a820L
	const-wide v0, 0xe2ae986673e14affL
	xor-long/2addr v4, v0
	sub-long v205, v105, v251
	sub-int v196, v151, v110
	const v1, 0x8498eb5a
	neg-float v2, v1
	sub-float/2addr v2, v1
	xor-long v174, v222, v105
	add-int/2addr v10, v7
	or-long v23, v174, v222
	double-to-long v4, v11
	add-int v53, v43, v116
	ushr-int v71, v8, v87
	add-int v157, v50, v227
	mul-float v181, v229, v189
	const-wide v23, 2048L
	or-long v23, v23, v23
	div-long v25, v55, v23
	rsub-int/lit8 v132, v53, -30
	or-int/lit8 v53, v53, 24
	rem-int v26, v173, v53
	xor-int/2addr v14, v8
	ushr-int v43, v151, v26
	shr-long v193, v55, v41
	not-int v15, v10
	rem-int/lit8 v139, v42, -62
	float-to-double v12, v1
	sub-long v233, v23, v55
	xor-int/lit16 v3, v8, -8313
	div-float/2addr v1, v2
	div-int/lit16 v5, v3, -12344
	or-int/lit16 v12, v10, -9984
	or-int/lit8 v11, v43, 121
	div-float/2addr v1, v2
	mul-int/lit8 v90, v132, -52
	xor-int/lit16 v14, v7, -26655
	not-int v6, v8
	or-int/lit16 v1, v7, -8225
	add-int v211, v15, v41
	and-long v127, v251, v55
	shl-int/2addr v6, v1
	add-float v134, v48, v2
	const-wide v1, 0x90035a61d6fbc0c8L
	double-to-float v4, v1
	float-to-long v6, v4
	neg-int v0, v10
	xor-int/2addr v11, v14
	long-to-int v4, v6
	shl-int/2addr v3, v12
	long-to-double v0, v6
	long-to-float v11, v6
	mul-double v130, v32, v244
	or-int/lit8 v41, v41, 63
	rem-int v27, v192, v41
	shr-int/2addr v4, v14
	const-wide v105, 16384L
	or-long v23, v23, v105
	div-long v189, v105, v23
	shr-int v14, v5, v4
	shl-long/2addr v6, v4
	add-float v213, v229, v134
	ushr-long v204, v193, v43
	const-wide v13, 0x64ffea507f361785L
	and-long/2addr v6, v13
	sub-int/2addr v10, v4
	const v14, 0x637939b9
	div-float/2addr v11, v14
	shl-int/lit8 v7, v5, -6
	shl-int/2addr v7, v8
	const-wide v13, 0xae5703e08e3f3aa5L
	const-wide v9, 0x7f346b43bb9a28e6L
	const-wide v174, 4096L
	or-long v9, v9, v174
	rem-long/2addr v13, v9
	div-int/lit8 v67, v61, 83
	const-wide v11, 0x90e935903a6756d1L
	mul-double/2addr v0, v11
	shr-long v30, v9, v28
	rsub-int/lit8 v52, v211, 109
	mul-int v178, v110, v132
	div-int/lit8 v147, v110, 41
	div-double/2addr v0, v11
	mul-float v109, v79, v181
	rem-int/lit8 v200, v151, 101
	or-long v181, v193, v189
	const-wide v204, 512L
	or-long v13, v13, v204
	rem-long/2addr v9, v13
	int-to-char v4, v7
	div-int/lit8 v149, v91, -52
	mul-long v215, v222, v251
	xor-long/2addr v13, v9
	shr-int/2addr v3, v15
	shr-long/2addr v9, v5
	const v3, 0xe82c4af8
	const v0, 0xd4d6110b
	sub-float/2addr v0, v3
	move-wide/from16 v15, v230
	mul-double/2addr v11, v15
	add-long v172, v55, v215
	rem-float/2addr v3, v0
	double-to-int v8, v15
	shl-int v225, v200, v50
	int-to-long v0, v7
	and-int v105, v52, v27
	div-double/2addr v11, v15
	sub-double/2addr v11, v15
	ushr-long v114, v13, v87
	mul-int v221, v178, v152
	add-float v219, v48, v134
	long-to-double v7, v0
	sub-long v12, v204, v174
	sub-int/2addr v4, v5
	xor-int/lit16 v13, v5, 9157
	mul-double v117, v68, v130
	xor-int/2addr v4, v5
	neg-long v6, v9
	mul-int/lit8 v89, v151, -108
	neg-int v10, v4
	const-wide v13, 0xeb2588ab10a8c1cL
	sub-double/2addr v15, v13
	const-wide v189, 512L
	or-long v0, v0, v189
	div-long/2addr v6, v0
	shl-long/2addr v6, v4
	sub-int/2addr v5, v4
	const v13, 0x52645d90
	add-float/2addr v13, v3
	or-int/2addr v5, v4
	const-wide v5, 0xc3d355557b071c1eL
	div-double/2addr v5, v15
	ushr-long/2addr v0, v4
	ushr-long/2addr v0, v10
	shr-long v39, v222, v50
	or-int v84, v151, v67
	mul-float/2addr v13, v3
	sub-float/2addr v3, v13
	and-long v116, v97, v127
	sub-int/2addr v4, v10
	shl-long v189, v114, v200
	shr-int/2addr v10, v4
	shl-int/2addr v10, v4
	shl-long v132, v233, v132
	add-float/2addr v13, v3
	mul-int/2addr v4, v10
	const-wide v172, 8388608L
	or-long v116, v116, v172
	div-long v107, v181, v116
	double-to-int v14, v15
	shr-int v253, v71, v77
	int-to-byte v13, v4
	mul-int/lit16 v0, v10, 6229
	sub-long v217, v222, v189
	int-to-short v1, v13
	and-long v175, v97, v55
	const v13, 0x82a4b8fe
	mul-float/2addr v3, v13
	const-wide v11, 0x5b5a096e344f1829L
	const-wide v4, 0x7cd0c5f51b8398a1L
	mul-long/2addr v4, v11
	double-to-float v8, v15
	mul-long/2addr v11, v4
	long-to-float v7, v4
	const-wide v4, 256L
	or-long v172, v172, v4
	rem-long v189, v251, v172
	div-int/lit16 v15, v0, -32545
	shr-int/2addr v1, v14
	mul-float v6, v63, v219
	mul-int/lit16 v15, v1, 19209
	mul-float/2addr v8, v6
	xor-int/2addr v0, v1
	or-int/lit8 v1, v1, 87
	div-int/2addr v14, v1
	int-to-long v13, v10
	and-int/2addr v0, v15
	float-to-double v4, v8
	rem-int/lit16 v10, v1, 1966
	add-int v197, v225, v253
	const-wide v175, 512L
	or-long v175, v175, v175
	div-long v160, v23, v175
	const-wide v11, 0x36b18a9e1f1c7988L
	div-double/2addr v4, v11
	div-float v88, v229, v3
	or-int/lit8 v164, v157, 29
	or-int/lit8 v211, v211, 46
	rem-int v169, v38, v211
	rsub-int/lit8 v34, v200, -109
	rem-int/lit8 v212, v42, -76
	mul-double v175, v45, v130
	sub-int/2addr v1, v10
	sub-int v214, v61, v164
	or-int/lit8 v10, v10, 106
	rem-int/2addr v1, v10
	and-int/lit16 v13, v1, -4333
	int-to-long v9, v10
	or-int/lit8 v221, v221, 111
	rem-int v1, v89, v221
	or-int v243, v77, v1
	or-int/lit8 v192, v192, 61
	div-int v121, v27, v192
	neg-float v11, v8
	not-int v13, v13
	or-int/lit8 v71, v71, 76
	div-int v81, v90, v71
	rem-float v246, v219, v229
	long-to-float v10, v9
	shr-long v11, v189, v212
	or-long v242, v23, v39
	const-wide v4, 0xd7cb13c6dfbad0a9L
	and-long/2addr v11, v4
	add-int/lit16 v7, v0, -21362
	shr-long/2addr v11, v13
	mul-int/lit8 v161, v227, 108
	neg-int v2, v0
	add-long v133, v233, v181
	shl-long v203, v233, v169
	sub-float v9, v213, v219
	add-int/lit8 v210, v212, -53
	sub-double v35, v32, v45
	xor-long v213, v97, v4
	const-wide v1, 0x5b80059828dd7c93L
	const-wide v4, 0xb639e544f4ebd7daL
	mul-double/2addr v1, v4
	or-int/2addr v15, v13
	or-int/lit8 v38, v38, 96
	rem-int v171, v0, v38
	rem-float v93, v6, v88
	add-double/2addr v1, v4
	const-wide v8, 0x5aafea86d742437cL
	mul-long/2addr v11, v8
	rem-double/2addr v1, v4
	mul-double/2addr v4, v1
	mul-int v95, v34, v152
	int-to-float v7, v7
	neg-double v1, v4
	long-to-float v5, v11
	div-int/lit16 v0, v15, -24757
	and-int v176, v52, v200
	xor-long/2addr v8, v11
	int-to-char v3, v13
	ushr-long/2addr v11, v15
	div-int/lit16 v5, v0, 10862
	div-float/2addr v7, v6
	neg-long v4, v8
	xor-int v90, v26, v71
	div-int/lit8 v118, v176, 2
	long-to-float v13, v11
	const-wide v193, 33554432L
	or-long v8, v8, v193
	rem-long/2addr v11, v8
	neg-float v10, v6
	add-float/2addr v7, v6
	const-wide v222, 512L
	or-long v30, v30, v222
	div-long v9, v133, v30
	rem-double v209, v1, v45
	shl-int/2addr v0, v15
	const-wide v0, 0xb195026e57e36b49L
	const-wide v15, 0x415b5d2414378552L
	add-double/2addr v15, v0
	add-long v154, v193, v233
	const-wide v97, 2097152L
	or-long v4, v4, v97
	div-long v44, v215, v4
	const v6, 0x69c23e27
	xor-int/2addr v3, v6
	add-float/2addr v7, v13
	sub-double v13, v230, v68
	double-to-long v2, v13
	add-int/lit16 v4, v6, 8563
	add-int/lit8 v228, v197, 111
	add-double/2addr v15, v0
	mul-int v103, v4, v110
	sub-int/2addr v6, v4
	add-long v107, v55, v193
	xor-long/2addr v9, v2
	neg-float v1, v7
	rem-float/2addr v7, v1
	xor-int/2addr v4, v6
	mul-float v179, v109, v79
	const-wide v222, 536870912L
	or-long v233, v233, v222
	rem-long v96, v30, v233
	and-int/2addr v4, v6
	ushr-int v97, v27, v164
	rem-double v85, v13, v209
	add-long/2addr v2, v11
	or-int/2addr v6, v4
	ushr-int/2addr v4, v6
	shr-int/2addr v4, v6
	add-double v204, v85, v13
	float-to-double v12, v7
	and-long v84, v172, v2
	sub-float v126, v246, v48
	shl-long/2addr v9, v6
	rem-int/lit16 v7, v4, -12151
	or-long/2addr v2, v9
	double-to-long v11, v15
	sub-float v99, v93, v58
	long-to-double v0, v9
	double-to-int v5, v0
	rem-double v99, v35, v32
	rem-int/lit16 v0, v5, 4555
	or-int/lit8 v4, v4, 4
	div-int/2addr v7, v4
	ushr-int/lit8 v131, v171, -70
	sub-double v235, v15, v204
	const v0, 0xf2882d57
	move/from16 v15, v261
	sub-float/2addr v15, v0
	mul-int v132, v95, v212
	add-int/2addr v6, v5
	mul-long/2addr v2, v9
	const-wide v3, 0xeca6022d67754ea6L
	const-wide v4, 0xfe0ecbd92101a84dL
	const-wide v4, 0x6e214097882e5d65L
	const-wide v15, 0x809a47591d5c6970L
	sub-double/2addr v15, v4
	const-wide v84, 8192L
	or-long v251, v251, v84
	rem-long v159, v9, v251
	ushr-int/lit8 v216, v192, 46
	mul-double/2addr v4, v15
	long-to-double v2, v11
	mul-long v215, v193, v154
	or-int/lit8 v78, v81, -94
	add-double/2addr v4, v15
	xor-long v63, v159, v44
	shl-int/2addr v6, v7
	shr-int v59, v95, v227
	int-to-float v0, v7
	add-double v78, v230, v204
	neg-long v12, v9
	not-int v6, v6
	shl-long/2addr v12, v7
	const v9, 0x78246aa
	rem-float/2addr v0, v9
	sub-int/2addr v7, v6
	add-double v120, v32, v2
	long-to-double v11, v12
	xor-long v128, v251, v63
	xor-int/lit8 v26, v221, -84
	neg-double v11, v4
	and-int/lit16 v1, v7, -28654
	shr-long v86, v172, v61
	const-wide v10, 0xc76f79c7667fa6d5L
	const-wide v3, 0x9e548fad48f73b52L
	and-long/2addr v10, v3
	sub-int v97, v161, v43
	not-long v13, v10
	or-int/2addr v6, v1
	move-wide/from16 v4, v230
	rem-double/2addr v4, v15
	neg-double v15, v15
	add-double/2addr v15, v4
	shl-long v167, v154, v50
	add-float/2addr v9, v0
	neg-double v6, v15
	add-int v227, v38, v59
	float-to-long v7, v0
	double-to-long v8, v15
	div-float v177, v246, v0
	mul-double/2addr v4, v15
	not-long v8, v10
	mul-float v223, v229, v219
	not-int v2, v1
	const v14, 0x6cb0d9ac
	add-float/2addr v0, v14
	shl-long/2addr v8, v1
	mul-long/2addr v10, v8
	sub-float v51, v58, v109
	div-float v26, v177, v179
	rem-float/2addr v0, v14
	long-to-float v7, v8
	ushr-long/2addr v8, v1
	rem-float v114, v48, v51
	long-to-double v8, v8
	xor-int v196, v192, v61
	xor-int/lit16 v10, v2, 31057
	ushr-long v250, v30, v105
	const-wide v8, 0x45e769c721e4a007L
	const-wide v9, 0xa918ae1b4ba28399L
	const-wide v2, 0x276a2d4e744c0a4aL
	mul-long/2addr v2, v9
	shr-long v84, v2, v169
	div-float v27, v93, v177
	float-to-int v6, v14
	xor-int/2addr v1, v6
	div-float/2addr v14, v0
	or-int v166, v34, v71
	or-long v57, v213, v23
	int-to-byte v8, v1
	mul-double/2addr v15, v4
	int-to-byte v12, v1
	float-to-long v11, v14
	int-to-long v14, v1
	mul-int/lit8 v46, v149, 47
	add-int/lit8 v101, v53, 5
	or-long v248, v193, v44
	ushr-long/2addr v11, v6
	shr-int/2addr v1, v8
	xor-int/lit8 v142, v164, 24
	shl-long v171, v39, v152
	sub-float/2addr v7, v0
	rem-float/2addr v0, v7
	div-double v155, v32, v209
	double-to-long v2, v4
	add-int/lit16 v15, v6, 25081
	ushr-int/2addr v6, v15
	div-int/lit16 v6, v6, -6144
	const-wide v6, 0x76c7b7604d46d651L
	div-double/2addr v4, v6
	int-to-long v2, v8
	neg-int v10, v1
	add-long v202, v193, v86
	int-to-double v0, v10
	shl-long/2addr v2, v10
	int-to-byte v9, v10
	not-int v15, v10
	const v14, 0xe7393e87
	const v2, 0x6c468623
	mul-float/2addr v2, v14
	sub-long v32, v116, v39
	and-long v85, v84, v233
	const-wide v14, 0x849e814fcd64852eL
	add-long/2addr v14, v11
	mul-int/lit8 v210, v42, 81
	mul-double/2addr v4, v6
	mul-int/lit8 v72, v101, 77
	neg-int v8, v8
	shl-int v23, v61, v169
	int-to-char v13, v9
	add-float v29, v27, v177
	float-to-int v11, v2
	ushr-long/2addr v14, v9
	mul-double/2addr v6, v0
	const-wide v1, 0x1ac8ccf3aaa172bfL
	or-long/2addr v14, v1
	or-int/lit8 v10, v10, 54
	rem-int/2addr v13, v10
	const v3, 0xab05183e
	const v12, 0x24f8724a
	sub-float/2addr v12, v3
	long-to-int v5, v1
	and-long v17, v217, v1
	double-to-long v8, v6
	sub-double v221, v68, v235
	mul-float v76, v229, v177
	ushr-long/2addr v14, v13
	neg-float v9, v3
	or-int v154, v46, v81
	xor-long/2addr v1, v14
	xor-int/lit8 v24, v90, -76
	sub-float v71, v88, v76
	float-to-long v6, v9
	mul-int/2addr v5, v10
	float-to-double v0, v9
	or-long/2addr v6, v14
	int-to-short v7, v13
	sub-double v105, v204, v0
	or-int/lit16 v8, v5, 26260
	add-double v147, v120, v235
	neg-float v5, v12
	rem-int/lit8 v194, v131, -19
	not-int v7, v10
	sub-long v137, v116, v159
	shl-long v93, v133, v24
	xor-long v125, v202, v217
	or-long v37, v215, v44
	mul-double v23, v68, v204
	sub-long v253, v93, v167
	sub-int/2addr v7, v11
	const-wide v9, 0xfcf5157ac682fd40L
	and-long/2addr v14, v9
	double-to-float v14, v0
	div-float v54, v3, v27
	and-long v122, v125, v9
	shr-int v74, v176, v142
	xor-int/2addr v8, v7
	const-wide v242, 2048L
	or-long v37, v37, v242
	rem-long v18, v122, v37
	int-to-double v8, v8
	div-int/lit16 v2, v13, -30075
	const-wide v1, 0xa04e30a6851b9e6L
	ushr-long/2addr v1, v13
	int-to-float v6, v7
	mul-int/2addr v13, v7
	add-double v254, v23, v105
	mul-double v193, v204, v120
	mul-long v14, v18, v1
	shl-long v195, v37, v52
	div-double v6, v204, v35
	xor-int v214, v72, v95
	mul-int v147, v43, v77
	sub-double v213, v235, v120
	rem-int/lit8 v143, v149, 95
	double-to-long v5, v6
	add-int/2addr v11, v13
	and-int v61, v211, v103
	not-int v12, v11
	sub-long/2addr v5, v1
	int-to-float v7, v13
	shl-long v211, v14, v149
	shr-long/2addr v1, v13
	const-wide v14, 0xdab978227a7762a1L
	rem-double/2addr v14, v8
	const-wide v55, 134217728L
	or-long v122, v122, v55
	div-long v154, v107, v122
	and-long v239, v189, v55
	or-int/lit8 v81, v81, 66
	rem-int v163, v72, v81
	and-int/lit8 v137, v89, -33
	int-to-double v1, v11
	shr-long/2addr v5, v11
	shr-int v8, v81, v164
	rem-float v11, v3, v88
	const-wide v133, 8L
	or-long v57, v57, v133
	rem-long v67, v248, v57
	long-to-double v10, v5
	int-to-char v11, v8
	sub-double v228, v244, v204
	rem-float/2addr v3, v7
	float-to-double v13, v3
	and-int v70, v103, v11
	int-to-byte v5, v8
	and-int/lit8 v36, v110, 67
	or-int v6, v192, v143
	sub-double/2addr v1, v13
	add-int/lit16 v6, v12, -3350
	add-long v196, v122, v171
	const-wide v4, 0x711ac36e388f0ab3L
	const-wide v2, 0xe098dfd3a440a3b0L
	and-long/2addr v2, v4
	add-double v235, v235, v105
	add-int/lit16 v8, v8, 21312
	int-to-byte v8, v8
	double-to-float v1, v13
	shl-int v6, v90, v178
	const-wide v159, 1048576L
	or-long v125, v125, v159
	rem-long v33, v133, v125
	and-int/lit16 v0, v11, 8756
	ushr-long/2addr v4, v6
	or-long v219, v217, v63
	xor-int/lit8 v7, v103, 112
	const-wide v11, 0x93f7d6ffbe404f8aL
	div-double/2addr v13, v11
	rem-double/2addr v13, v11
	and-int/lit8 v201, v169, -70
	rem-double v53, v23, v193
	neg-int v12, v0
	rsub-int v4, v7, -6132
	and-int v171, v0, v178
	mul-double v67, v230, v221
	int-to-long v3, v7
	const-wide v9, 0xc3e65749b5ad79deL
	or-long/2addr v9, v3
	mul-double v134, v13, v204
	div-float v13, v114, v88
	shl-int/2addr v12, v8
	int-to-short v14, v12
	const-wide v55, 536870912L
	or-long v217, v217, v55
	div-long v9, v211, v217
	not-long v4, v3
	div-int/lit16 v13, v8, -2785
	long-to-double v6, v9
	mul-int/2addr v13, v12
	int-to-byte v12, v0
	add-float v38, v223, v48
	ushr-int/2addr v8, v12
	xor-int/lit8 v48, v41, 7
	const-wide v93, 268435456L
	or-long v4, v4, v93
	rem-long/2addr v9, v4
	int-to-float v5, v14
	int-to-char v13, v0
	rem-double v160, v213, v204
	const-wide v14, 0xddfb988b76c09350L
	sub-long/2addr v14, v9
	or-int/lit16 v12, v12, -22184
	mul-long v92, v30, v167
	neg-int v15, v12
	const-wide v39, 16384L
	or-long v18, v18, v39
	rem-long v59, v44, v18
	const-wide v10, 0x781c9d1255aeb5c1L
	const-wide v15, 0xa2246f7a9d68d481L
	add-long/2addr v10, v15
	sub-float/2addr v5, v1
	int-to-long v14, v8
	mul-int v87, v43, v149
	const-wide v5, 0xa6c194806c0f4b05L
	const-wide v11, 0x6753b74fa5ac27bcL
	rem-double/2addr v11, v5
	div-int/lit8 v125, v201, 19
	rem-int/lit8 v88, v77, 116
	int-to-short v5, v13
	and-int/lit8 v7, v42, -88
	add-int/lit8 v137, v176, 9
	const-wide v0, 0x8eae1877b21d5122L
	or-long/2addr v0, v14
	const-wide v18, 536870912L
	or-long v14, v14, v18
	rem-long/2addr v0, v14
	const v8, 0x2251e2c6
	const v13, 0xe9899b94
	sub-float/2addr v8, v13
	or-int/lit8 v5, v5, 49
	div-int/2addr v7, v5
	shr-int/2addr v5, v7
	shr-int/lit8 v123, v132, -29
	div-int/lit8 v17, v90, 10
	double-to-long v10, v11
	mul-int v127, v17, v5
	const-wide v5, 0x499f6e73c3c4b9f4L
	const-wide v1, 0x6d4e30ff5f4188cbL
	div-double/2addr v5, v1
	or-int v193, v52, v118
	double-to-int v3, v1
	or-int/lit8 v52, v52, 41
	rem-int v96, v201, v52
	shl-int/2addr v3, v7
	add-float v1, v13, v76
	shl-int/2addr v3, v7
	mul-int/lit16 v8, v3, -27715
	div-int/lit16 v9, v7, -24678
	or-int v84, v125, v70
	div-double v101, v204, v53
	neg-double v4, v5
	mul-double v223, v221, v120
	or-int/lit8 v8, v8, 45
	div-int/2addr v9, v8
	or-int/2addr v9, v7
	not-int v0, v7
	or-int/lit8 v46, v46, 53
	rem-int v10, v178, v46
	shl-int v218, v225, v81
	xor-int/lit8 v68, v48, -39
	const-wide v12, 0x873af1d3d04e90daL
	sub-long/2addr v12, v14
	or-int/lit8 v0, v0, 63
	rem-int/2addr v9, v0
	mul-int/2addr v3, v9
	not-int v14, v9
	sub-int/2addr v8, v10
	rem-float v88, v177, v109
	rem-double v208, v160, v228
	float-to-long v8, v1
	rsub-int v5, v10, 20119
	mul-long v10, v116, v8
	const-wide v2, 0xa1e318bf6a30969fL
	const-wide v10, 0x9c5e7ae26de2bbccL
	add-double/2addr v10, v2
	or-int v36, v210, v193
	const v5, 0x6d7611b7
	sub-float/2addr v5, v1
	div-float v27, v38, v179
	not-long v3, v8
	sub-long v82, v85, v107
	xor-long/2addr v12, v3
	sub-float v182, v5, v177
	ushr-long v158, v3, v0
	shr-int/lit8 v103, v42, 72
	double-to-int v8, v10
	not-int v8, v7
	xor-int v6, v84, v127
	neg-int v15, v7
	add-double v110, v228, v120
	mul-float/2addr v5, v1
	add-int v251, v103, v43
	shr-long/2addr v12, v8
	div-float/2addr v5, v1
	mul-int/2addr v7, v15
	shl-int v217, v192, v8
	or-int v201, v61, v139
	or-int/lit8 v6, v6, 123
	rem-int/2addr v0, v6
	and-int/lit8 v146, v217, 43
	const-wide v8, 0xdbfb466f065ae930L
	div-double/2addr v10, v8
	div-double/2addr v8, v10
	not-int v14, v15
	xor-long v160, v107, v85
	shr-long v232, v233, v6
	or-int/2addr v0, v6
	or-int/lit8 v50, v147, -77
	mul-int/lit16 v11, v7, 29264
	int-to-char v1, v15
	add-long v132, v215, v55
	add-int/lit8 v89, v0, 108
	shr-int/2addr v0, v14
	add-int/lit16 v12, v1, -18827
	mul-int/lit8 v135, v89, -43
	xor-int/2addr v6, v1
	int-to-float v9, v6
	mul-long v148, v211, v3
	xor-int/2addr v6, v1
	or-int/lit8 v15, v15, 80
	div-int/2addr v7, v15
	div-float v46, v38, v177
	neg-long v7, v3
	neg-long v13, v7
	mul-float/2addr v5, v9
	const-wide v14, 0xb87d20026d45a47aL
	const-wide v8, 0x22c906d0f1889e4bL
	mul-double/2addr v8, v14
	int-to-long v13, v1
	neg-long v10, v13
	rem-int/lit8 v89, v163, 30
	ushr-int/lit8 v126, v164, 42
	const v11, 0x5f7e415c
	mul-float/2addr v5, v11
	or-int/lit16 v7, v1, 18068
	double-to-int v9, v8
	int-to-float v6, v1
	add-int/lit8 v123, v169, 26
	sub-long v86, v3, v154
	ushr-int/2addr v7, v12
	const-wide v0, 0xd095fd636ff239L
	move-wide/from16 v10, v235
	rem-double/2addr v0, v10
	and-int/lit8 v114, v126, -25
	or-int/lit8 v9, v9, 45
	div-int/2addr v12, v9
	double-to-long v5, v0
	mul-int/lit8 v247, v41, -13
	mul-int/lit8 v48, v127, 25
	const v2, 0x37726d06
	const v4, 0x46989cc1
	rem-float/2addr v4, v2
	not-long v1, v5
	div-int/lit16 v10, v9, 24146
	float-to-long v11, v4
	move/from16 v15, v88
	rem-float/2addr v4, v15
	div-float v170, v46, v27
	xor-long/2addr v1, v11
	mul-float/2addr v4, v15
	and-int/lit8 v122, v251, -67
	xor-int v65, v151, v164
	const-wide v196, 1048576L
	or-long v158, v158, v196
	rem-long v189, v92, v158
	shr-int v207, v41, v217
	shr-int v17, v89, v43
	move-wide/from16 v14, v120
	double-to-long v0, v14
	rem-int/lit8 v91, v143, -75
	and-int/2addr v9, v10
	mul-double v183, v204, v99
	const-wide v13, 0x9baa5e0a30e10838L
	const-wide v11, 0x174a0ab9bb390b8bL
	mul-double/2addr v13, v11
	int-to-byte v14, v9
	rsub-int/lit8 v194, v42, 87
	or-int/lit8 v7, v7, 74
	div-int/2addr v10, v7
	and-long v218, v33, v202
	rem-float v56, v4, v51
	const-wide v132, 32768L
	or-long v242, v242, v132
	div-long v150, v189, v242
	add-long v161, v44, v107
	ushr-long/2addr v0, v7
	shl-int/lit8 v66, v52, -15
	shr-int/lit8 v124, v125, 6
	long-to-int v13, v5
	or-int/lit16 v8, v7, 20483
	div-double v93, v183, v99
	add-int/lit8 v36, v157, -71
	or-int/lit8 v13, v13, 109
	rem-int/2addr v10, v13
	const-wide v211, 128L
	or-long v0, v0, v211
	div-long/2addr v5, v0
	float-to-double v7, v4
	add-int v236, v152, v193
	const v14, 0x8c8060fe
	div-float/2addr v14, v4
	and-int/lit8 v9, v157, -61
	sub-double/2addr v7, v11
	mul-int/2addr v13, v9
	or-int/lit8 v10, v10, 84
	rem-int/2addr v9, v10
	mul-double v130, v213, v23
	ushr-int/2addr v9, v13
	mul-double v151, v7, v11
	or-int/lit8 v189, v50, -73
	long-to-int v9, v5
	xor-int v47, v135, v176
	mul-float/2addr v14, v4
	int-to-float v14, v13
	rem-float/2addr v4, v14
	mul-int/lit8 v105, v81, -101
	div-double/2addr v7, v11
	xor-int/lit16 v3, v13, 18373
	xor-long/2addr v0, v5
	sub-long v173, v148, v232
	const-wide v86, 524288L
	or-long v5, v5, v86
	rem-long/2addr v0, v5
	double-to-long v7, v11
	float-to-int v5, v14
	double-to-float v12, v11
	and-int/lit8 v183, v5, -14
	int-to-short v8, v13
	ushr-int v56, v10, v217
	xor-int/2addr v5, v8
	div-float/2addr v14, v12
	add-int/lit8 v61, v176, 17
	int-to-byte v1, v13
	rem-double v111, v228, v93
	add-int/lit8 v30, v72, 94
	move-wide/from16 v7, v53
	double-to-int v0, v7
	and-int/lit16 v4, v10, -28011
	rsub-int v12, v3, -24786
	int-to-long v5, v9
	int-to-byte v9, v13
	mul-int/2addr v12, v1
	sub-int v233, v61, v36
	mul-int/lit8 v75, v68, 93
	or-int/lit8 v169, v169, 24
	rem-int v213, v13, v169
	xor-int/lit16 v14, v13, 15625
	sub-int v74, v74, v70
	int-to-short v1, v14
	sub-double v38, v221, v78
	xor-long v95, v5, v248
	shr-int v246, v36, v164
	add-float v7, v76, v46
	const v12, 0x556b0a80
	sub-float/2addr v7, v12
	or-int/lit8 v251, v251, 26
	rem-int v112, v233, v251
	sub-long v232, v95, v59
	add-int/lit8 v57, v217, -88
	move-wide/from16 v12, v215
	const-wide v154, 256L
	or-long v5, v5, v154
	div-long/2addr v12, v5
	add-int/2addr v10, v1
	int-to-double v11, v1
	long-to-int v11, v5
	add-int v173, v225, v126
	shl-long v170, v196, v143
	const v14, 0x5905d1d3
	rem-float/2addr v14, v7
	xor-int/2addr v10, v1
	rem-float v144, v88, v51
	shl-long/2addr v5, v0
	const-wide v14, 0x48301cea5d657950L
	const-wide v1, 0xbd549de479a10196L
	mul-double/2addr v1, v14
	and-int/2addr v3, v0
	shl-int/2addr v4, v0
	const-wide v44, 2L
	or-long v59, v59, v44
	div-long v154, v148, v59
	rem-double/2addr v1, v14
	ushr-long/2addr v5, v0
	const-wide v15, 0x7e2bd9da9bd07af9L
	and-long/2addr v15, v5
	or-long v166, v196, v59
	and-long/2addr v15, v5
	div-double v235, v254, v130
	add-double v218, v221, v101
	add-int/2addr v3, v11
	const v15, 0x2c430673
	mul-float/2addr v15, v7
	not-int v11, v11
	ushr-int/lit8 v88, v157, -89
	mul-int/lit8 v34, v114, 117
	mul-int/lit8 v181, v189, 19
	div-int/lit8 v57, v192, -64
	sub-float/2addr v15, v7
	const-wide v166, 536870912L
	or-long v18, v18, v166
	rem-long v45, v158, v18
	shl-int/lit8 v30, v225, -8
	xor-long v147, v248, v161
	neg-double v12, v1
	xor-int/2addr v3, v9
	or-long v175, v59, v116
	shl-long v242, v147, v43
	ushr-int/lit8 v51, v178, -9
	move-wide/from16 v13, v263
	xor-long/2addr v5, v13
	float-to-double v0, v7
	int-to-byte v10, v11
	sub-int/2addr v3, v11
	sub-float v178, v76, v15
	not-int v0, v9
	long-to-float v14, v5
	float-to-long v4, v14
	ushr-int/2addr v9, v11
	shl-long/2addr v4, v9
	or-int/2addr v3, v10
	div-int/lit8 v206, v43, -8
	int-to-byte v9, v9
	const-wide v166, 512L
	or-long v86, v86, v166
	rem-long v149, v4, v86
	int-to-byte v1, v11
	const-wide v0, 0x1a57ab07119156eL
	const-wide v202, 65536L
	or-long v4, v4, v202
	div-long/2addr v0, v4
	const-wide v0, 0x6c75113c111a48d9L
	double-to-int v14, v0
	or-long v35, v170, v18
	add-float/2addr v15, v7
	rsub-int v10, v3, -31719
	const-wide v11, 0xe9a61452ccf610deL
	div-double/2addr v0, v11
	or-int/lit8 v30, v30, 43
	rem-int v103, v10, v30
	sub-float/2addr v7, v15
	and-int/lit8 v109, v52, 25
	sub-long v97, v107, v239
	sub-float/2addr v15, v7
	ushr-int v189, v103, v173
	ushr-long/2addr v4, v14
	float-to-long v9, v15
	or-int/lit8 v251, v251, 57
	div-int v18, v34, v251
	rsub-int v4, v3, 25053
	mul-int v16, v217, v14
	long-to-double v3, v9
	add-double/2addr v3, v0
	or-long v216, v166, v175
	const-wide v8, 0x2951a9e61640b2e9L
	const-wide v4, 0x45ae02f5f8d151e0L
	const-wide v170, 64L
	or-long v8, v8, v170
	rem-long/2addr v4, v8
	mul-int v250, v89, v181
	shl-long/2addr v4, v14
	sub-float v75, v179, v7
	or-long v196, v107, v8
	mul-int/lit8 v183, v48, 85
	rem-double v208, v101, v204
	sub-float v245, v75, v27
	neg-float v3, v15
	or-long v61, v248, v35
	const v9, 0x7071354c
	add-int/2addr v14, v9
	add-float/2addr v3, v15
	neg-float v4, v15
	add-int/lit16 v7, v9, -8567
	rem-double v178, v120, v230
	const-wide v7, 0xae529e045fdea57dL
	long-to-int v11, v7
	xor-int/2addr v9, v11
	or-int/lit8 v14, v14, 89
	div-int/2addr v11, v14
	int-to-float v14, v14
	const-wide v154, 4194304L
	or-long v35, v35, v154
	rem-long v133, v166, v35
	const-wide v86, 16L
	or-long v95, v95, v86
	div-long v252, v133, v95
	rsub-int v5, v9, 2297
	mul-int/lit16 v11, v9, -13393
	and-int/lit8 v8, v250, -83
	div-int/lit8 v6, v17, 73
	sub-float/2addr v4, v3
	shr-long v92, v166, v207
	or-int v60, v251, v225
	move-wide/from16 v9, v178
	sub-double/2addr v0, v9
	sub-float/2addr v3, v4
	shl-int v140, v50, v72
	shl-int v72, v164, v8
	const-wide v11, 0x68080fe30dfc6ceL
	const-wide v3, 0xc712ffdc943b80b9L
	add-long/2addr v11, v3
	or-int/lit8 v164, v164, 48
	rem-int v115, v140, v164
	div-int/lit16 v8, v8, -6827
	shr-int/lit8 v100, v251, -126
	sub-long/2addr v3, v11
	mul-double v142, v178, v101
	neg-int v3, v8
	ushr-long v159, v133, v56
	const-wide v15, 0x6bcd355c5e7b39ecL
	const-wide v202, 128L
	or-long v15, v15, v202
	div-long/2addr v11, v15
	const v8, 0xbdb5042c
	rem-float/2addr v14, v8
	const-wide v175, 4096L
	or-long v166, v166, v175
	rem-long v178, v159, v166
	rem-double v223, v223, v53
	rem-float/2addr v8, v14
	mul-int/lit8 v232, v89, 112
	xor-long v21, v97, v128
	neg-int v14, v5
	add-int/2addr v3, v6
	and-long v141, v170, v154
	mul-long/2addr v15, v11
	add-double v49, v38, v230
	float-to-double v0, v8
	or-int/lit16 v5, v6, 25235
	mul-long/2addr v15, v11
	add-double/2addr v9, v0
	and-long v19, v239, v86
	double-to-long v6, v9
	rem-double/2addr v0, v9
	or-int/lit8 v157, v157, 56
	rem-int v146, v181, v157
	shr-int/2addr v3, v14
	shl-long/2addr v11, v5
	shl-long v96, v86, v181
	rem-float v40, v29, v75
	int-to-byte v15, v5
	or-int/lit8 v74, v74, 73
	rem-int v84, v15, v74
	ushr-int v33, v125, v51
	div-int/lit8 v240, v189, 111
	sub-int/2addr v3, v14
	shr-long v100, v133, v91
	shr-int v225, v157, v68
	long-to-float v7, v11
	or-int/lit8 v28, v28, 61
	div-int v205, v200, v28
	add-int/2addr v14, v15
	mul-long v252, v147, v202
	const-wide v8, 0x2ca024cfa7ec4a68L
	add-long/2addr v8, v11
	neg-double v8, v0
	rsub-int/lit8 v131, v137, 50
	rem-int/lit16 v2, v3, 1290
	const-wide v0, 0x3df6881e973327fL
	const-wide v107, 1048576L
	or-long v0, v0, v107
	rem-long/2addr v11, v0
	add-int/lit8 v114, v194, 30
	int-to-long v6, v14
	div-int/lit16 v11, v15, -18620
	const-wide v86, 16777216L
	or-long v6, v6, v86
	div-long/2addr v0, v6
	shr-long/2addr v0, v15
	xor-int/2addr v3, v5
	rem-int/lit8 v154, v240, 43
	add-int/lit16 v12, v3, 3487
	const-wide v170, 16384L
	or-long v21, v21, v170
	div-long v164, v6, v21
	mul-long/2addr v6, v0
	const-wide v2, 0xd36c629235952adL
	add-double/2addr v2, v8
	or-int/lit8 v193, v65, -3
	div-float v105, v177, v40
	and-long v131, v96, v159
	neg-long v1, v6
	xor-long/2addr v6, v1
	shr-int/lit8 v47, v173, 3
	const v9, 0xffa12503
	float-to-int v14, v9
	int-to-float v14, v11
	or-int/2addr v15, v5
	rem-int/lit8 v251, v227, 15
	xor-int/lit16 v4, v11, -18882
	sub-long/2addr v6, v1
	div-float/2addr v14, v9
	int-to-long v0, v5
	shr-long v65, v133, v154
	shr-long v29, v19, v181
	and-int/2addr v15, v5
	div-float v16, v26, v71
	float-to-double v5, v14
	ushr-int/2addr v11, v12
	or-long v156, v131, v216
	mul-int v111, v72, v77
	or-int/2addr v15, v4
	const-wide v2, 0xac6eecdbf4447d0fL
	const-wide v128, 262144L
	or-long v2, v2, v128
	rem-long/2addr v0, v2
	shl-int/2addr v4, v11
	div-int/lit16 v13, v11, 2575
	ushr-int/2addr v15, v11
	const-wide v159, 32L
	or-long v21, v21, v159
	rem-long v127, v252, v21
	sub-float v67, v71, v144
	and-int/lit16 v14, v15, -6790
	shr-int/lit8 v77, v122, 73
	rsub-int/lit8 v47, v140, 95
	neg-int v12, v14
	int-to-double v10, v12
	const-wide v92, 512L
	or-long v2, v2, v92
	div-long/2addr v0, v2
	mul-int v182, v201, v194
	long-to-double v12, v2
	mul-int/lit8 v173, v137, 63
	and-int/2addr v4, v14
	ushr-int/lit8 v110, v181, 46
	const v11, 0xccd3d93f
	mul-float/2addr v9, v11
	add-double v210, v49, v23
	neg-long v9, v0
	const-wide v96, 4096L
	or-long v166, v166, v96
	div-long v150, v21, v166
	add-long v170, v161, v29
	xor-long/2addr v2, v0
	shl-long v243, v21, v88
	div-float v224, v40, v27
	const-wide v196, 268435456L
	or-long v0, v0, v196
	rem-long/2addr v2, v0
	shr-int v52, v48, v109
	add-int/lit8 v130, v33, 2
	xor-int/2addr v4, v14
	double-to-int v7, v12
	xor-int v80, v251, v90
	sub-long v108, v107, v178
	shl-int/lit8 v212, v77, -17
	or-int/lit8 v15, v15, 104
	rem-int/2addr v7, v15
	const v2, 0xb2fa057c
	div-float/2addr v11, v2
	ushr-long/2addr v0, v7
	double-to-long v3, v5
	xor-int/lit16 v13, v15, -6342
	or-int/2addr v15, v7
	shl-int v201, v124, v246
	const-wide v11, 0xcedc25583c8a5849L
	add-double/2addr v11, v5
	sub-long v44, v127, v202
	or-int/lit16 v1, v15, -21975
	float-to-long v14, v2
	and-long/2addr v3, v14
	neg-int v10, v1
	and-int/lit16 v15, v1, 27377
	const-wide v1, 0x62d08e04ed28e1f2L
	add-long/2addr v1, v3
	rem-int/lit16 v5, v15, -2951
	mul-float v217, v144, v67
	and-int/2addr v7, v5
	not-int v4, v13
	const v10, 0xd0999c95
	const v12, 0xe1fc218b
	rem-float/2addr v10, v12
	add-float/2addr v10, v12
	or-int/lit16 v3, v5, -1349
	shr-int v109, v250, v163
	xor-int v58, v42, v183
	and-int/lit8 v170, v17, -105
	or-int/lit8 v15, v15, 22
	rem-int/2addr v13, v15
	ushr-int/2addr v3, v4
	rsub-int/lit8 v108, v60, -28
	const-wide v7, 0xd222c42798464442L
	neg-double v15, v7
	sub-long v141, v178, v86
	not-int v12, v5
	neg-double v3, v15
	const v9, 0xad430a5d
	rem-float/2addr v10, v9
	add-long v157, v131, v63
	or-int/lit16 v11, v12, -2388
	xor-long v72, v133, v243
	div-float/2addr v10, v9
	mul-double/2addr v15, v7
	or-long v66, v252, v82
	rem-int/lit16 v10, v12, -21019
	or-int v66, v17, v10
	long-to-int v12, v1
	shr-long/2addr v1, v13
	shr-int v207, v227, v247
	const-wide v13, 0xd6892274bed7c3a1L
	const-wide v100, 4194304L
	or-long v1, v1, v100
	div-long/2addr v13, v1
	shr-int/2addr v10, v5
	add-int/lit8 v145, v110, 53
	or-int/lit8 v130, v130, 66
	rem-int v208, v240, v130
	add-int/lit8 v209, v109, -121
	const v13, 0x4f730999
	rem-float/2addr v9, v13
	shl-long v184, v196, v80
	add-int/lit8 v18, v33, 108
	sub-int v80, v52, v48
	int-to-long v7, v12
	ushr-long/2addr v7, v10
	div-double v40, v78, v210
	div-int/lit16 v2, v11, 15489
	not-long v6, v7
	const-wide v10, 0xfa6c19e19620a281L
	const-wide v116, 1048576L
	or-long v6, v6, v116
	rem-long/2addr v10, v6
	and-int/2addr v12, v5
	rem-int/lit8 v161, v66, -68
	or-int/lit16 v10, v2, 14659
	or-int/2addr v12, v10
	add-long v65, v157, v44
	float-to-long v3, v13
	int-to-short v11, v12
	mul-int/lit16 v12, v10, 2637
	double-to-int v10, v15
	shl-int/lit8 v51, v60, 3
	rsub-int/lit8 v145, v111, 31
	int-to-float v15, v12
	and-long/2addr v3, v6
	not-long v11, v3
	const-wide v11, 0x4b11afa2dad06366L
	neg-double v3, v11
	shr-int/2addr v2, v10
	rem-double v93, v53, v11
	xor-int/2addr v2, v10
	or-int/lit8 v167, v91, 11
	shl-long/2addr v6, v5
	const-wide v1, 0xb9f9d9e1edac6a22L
	or-long/2addr v6, v1
	and-int/lit8 v219, v183, 6
	or-int/lit8 v5, v5, 125
	rem-int/2addr v10, v5
	sub-float/2addr v13, v15
	div-float v0, v76, v15
	rem-double/2addr v11, v3
	shl-long/2addr v1, v5
	float-to-int v0, v0
	mul-double v79, v38, v120
	ushr-long v140, v29, v209
	not-long v8, v6
	not-int v8, v10
	sub-double/2addr v3, v11
	div-double v54, v23, v40
	or-int/lit8 v88, v88, 45
	rem-int v2, v33, v88
	div-double/2addr v11, v3
	ushr-long v30, v61, v81
	not-long v13, v6
	mul-int/lit8 v50, v17, -77
	shl-int/lit8 v61, v125, -24
	or-int/lit8 v206, v206, 53
	div-int v253, v17, v206
	shr-int/2addr v10, v0
	int-to-long v8, v2
	add-double v59, v23, v254
	shl-int v87, v47, v212
	and-int v203, v167, v135
	xor-long v80, v19, v127
	and-long v218, v13, v82
	div-int/lit8 v16, v52, -64
	div-int/lit8 v85, v183, 28
	rem-int/lit16 v12, v0, -18572
	const v8, 0x39926922
	rem-float/2addr v15, v8
	xor-int/lit8 v168, v135, 13
	neg-int v9, v12
	sub-double v84, v254, v38
	not-long v4, v13
	sub-float v137, v71, v26
	add-long v26, v147, v178
	shr-long/2addr v13, v12
	float-to-long v6, v15
	long-to-int v2, v4
	or-int/lit8 v9, v9, 20
	div-int/2addr v10, v9
	const-wide v14, 0x842916788f96deb1L
	const-wide v1, 0xcd8adbf2624c02d8L
	sub-double/2addr v14, v1
	rsub-int/lit8 v223, v74, 123
	div-int/lit8 v248, v189, 36
	neg-int v8, v0
	int-to-byte v14, v10
	neg-double v10, v1
	mul-long v237, v218, v30
	or-int/lit8 v9, v9, 78
	div-int/2addr v14, v9
	add-int v171, v91, v14
	add-float v43, v76, v75
	shl-int v38, v240, v47
	ushr-long v246, v26, v118
	double-to-long v12, v1
	or-int/lit8 v109, v109, 26
	div-int v200, v90, v109
	rem-float v67, v105, v76
	neg-int v7, v9
	add-int/2addr v0, v8
	neg-double v15, v10
	int-to-short v7, v9
	shl-int v149, v57, v251
	sub-long/2addr v12, v4
	shr-long v58, v4, v163
	shl-int/2addr v8, v7
	rem-int/lit16 v3, v7, 4055
	or-int/lit8 v110, v110, 70
	rem-int v109, v161, v110
	rsub-int v11, v7, 23070
	const-wide v133, 4096L
	or-long v164, v164, v133
	rem-long v1, v44, v164
	div-int/lit8 v86, v208, 100
	sub-int/2addr v9, v14
	or-long/2addr v1, v12
	ushr-long/2addr v4, v14
	sub-long/2addr v1, v4
	const-wide v11, 0x7d79071b27c9996eL
	rem-double/2addr v15, v11
	mul-int v136, v130, v8
	long-to-float v10, v4
	double-to-float v15, v15
	shl-int v98, v183, v182
	rem-int/lit8 v91, v154, -24
	neg-float v2, v10
	or-int/lit8 v47, v47, 76
	div-int v229, v189, v47
	mul-float/2addr v10, v15
	mul-float v241, v144, v76
	add-int v124, v223, v77
	double-to-long v6, v11
	rem-float v146, v15, v67
	xor-int/lit16 v6, v8, -13983
	add-int/2addr v0, v3
	neg-float v5, v10
	mul-int/lit8 v36, v51, 50
	double-to-long v8, v11
	rsub-int/lit8 v125, v48, 81
	rem-double v180, v40, v230
	mul-int/lit16 v15, v6, -18167
	neg-int v11, v14
	neg-long v1, v8
	ushr-int v211, v192, v154
	neg-long v5, v8
	div-double v165, v254, v230
	shr-int/2addr v15, v0
	int-to-byte v11, v14
	add-int/lit16 v7, v11, -3199
	sub-long v252, v65, v116
	and-int/lit16 v2, v3, 12557
	or-long v154, v175, v252
	const-wide v0, 0xa05227fec4097198L
	double-to-long v2, v0
	add-long v35, v96, v159
	mul-int/lit16 v10, v7, 15637
	shr-int v10, v10, v17
	mul-long v234, v140, v5
	and-int v87, v17, v87
	add-long/2addr v2, v5
	add-int v153, v171, v169
	const-wide v0, 0xd123c0095d49a0b4L
	const-wide v6, 0x90295de36c7ee176L
	sub-double/2addr v0, v6
	rem-int/lit16 v1, v10, -25015
	ushr-long v68, v131, v61
	or-int/lit8 v208, v208, 42
	div-int v4, v77, v208
	const-wide v10, 0xfde6d5ec605a85f8L
	sub-double/2addr v6, v10
	int-to-byte v11, v1
	const v5, 0xbaa04b41
	const v12, 0x63927020
	sub-float/2addr v5, v12
	ushr-int v172, v149, v248
	or-int/lit8 v14, v14, 104
	div-int/2addr v15, v14
	const-wide v1, 0x795f5d76418d0e80L
	div-double/2addr v6, v1
	const-wide v1, 0x1fb90fd3e3800d16L
	sub-long/2addr v8, v1
	xor-int v38, v130, v211
	sub-double v224, v230, v165
	mul-double v48, v180, v54
	xor-long/2addr v1, v8
	or-int/2addr v15, v11
	sub-int/2addr v4, v14
	ushr-int/lit8 v97, v33, 79
	rem-int/lit16 v4, v11, 20113
	or-int/lit8 v212, v212, 124
	div-int v48, v74, v212
	div-int/lit16 v11, v11, -24904
	const-wide v82, 134217728L
	or-long v8, v8, v82
	rem-long/2addr v1, v8
	const-wide v13, 0xbaa96ed96f5fa418L
	sub-double/2addr v6, v13
	shl-long v146, v184, v98
	div-int/lit8 v244, v203, -48
	or-int/2addr v11, v15
	and-int/lit16 v9, v15, 9411
	div-double/2addr v6, v13
	xor-int/2addr v9, v15
	const-wide v0, 0x7eda79498475e304L
	move-wide/from16 v13, v150
	const-wide v150, 8388608L
	or-long v0, v0, v150
	div-long/2addr v13, v0
	const-wide v150, 1073741824L
	or-long v157, v157, v150
	div-long v119, v44, v157
	and-long/2addr v13, v0
	int-to-double v12, v4
	shl-int v60, v122, v123
	or-long v180, v44, v127
	const-wide v14, 0x6aa28d2980a861e7L
	const-wide v68, 1073741824L
	or-long v0, v0, v68
	rem-long/2addr v14, v0
	neg-double v2, v6
	shr-int v83, v212, v182
	add-long/2addr v14, v0
	neg-double v5, v6
	const v2, 0xa15bada
	const v10, 0xbf1fefd6
	rem-float/2addr v2, v10
	double-to-long v5, v12
	shr-int v140, v122, v200
	rsub-int/lit8 v33, v123, 2
	const-wide v2, 0xfec81ca6387242c9L
	sub-double/2addr v2, v12
	ushr-int v19, v125, v50
	add-double v106, v224, v230
	div-int/lit8 v107, v223, -83
	and-int/2addr v11, v4
	sub-long/2addr v14, v5
	div-int/lit16 v10, v11, 11323
	mul-long/2addr v0, v5
	double-to-long v12, v12
	xor-int/lit8 v186, v89, -67
	div-int/lit8 v229, v200, -80
	long-to-int v5, v12
	div-int/lit16 v3, v11, 12141
	const-wide v10, 0xf5e5f01b0338eee3L
	const-wide v7, 0x918765bcb8cb6b7cL
	mul-double/2addr v10, v7
	int-to-char v12, v9
	and-long v37, v159, v237
	rem-double/2addr v7, v10
	int-to-char v11, v3
	div-int/lit8 v125, v56, -59
	and-long/2addr v0, v14
	shr-int/lit8 v252, v98, 121
	div-int/lit8 v131, v9, -27
	mul-float v236, v217, v105
	not-int v3, v12
	shl-long v213, v72, v135
	sub-float v158, v137, v217
	rem-double v70, v254, v40
	add-double v103, v54, v23
	int-to-char v8, v5
	mul-int/lit8 v254, v139, -79
	ushr-int/lit8 v28, v201, 76
	or-long v241, v58, v154
	move-wide/from16 v0, v273
	double-to-int v8, v0
	const v1, 0xae8c4542
	move/from16 v3, v158
	rem-float/2addr v3, v1
	float-to-double v10, v1
	not-long v12, v14
	mul-long v242, v30, v133
	add-float v103, v76, v217
	or-int/2addr v8, v9
	shl-int/lit8 v115, v51, 50
	const-wide v5, 0xfb6699ee76638462L
	mul-double/2addr v10, v5
	sub-double/2addr v10, v5
	not-int v10, v9
	shr-long/2addr v12, v10
	xor-long/2addr v12, v14
	xor-int/2addr v9, v10
	shr-int/lit8 v86, v17, 108
	or-long/2addr v12, v14
	sub-int v95, v223, v88
	mul-int/2addr v8, v9
	mul-int/lit8 v165, v163, 33
	or-int/lit8 v9, v9, 99
	rem-int/2addr v8, v9
	mul-float v24, v103, v158
	float-to-double v1, v1
	rem-double/2addr v5, v1
	ushr-int/2addr v9, v4
	and-int/lit16 v3, v4, 18851
	shr-int v144, v83, v42
	neg-double v5, v1
	not-int v11, v4
	div-double v82, v230, v84
	sub-long v82, v100, v218
	sub-int/2addr v3, v8
	and-int v246, v112, v125
	neg-long v3, v14
	neg-long v9, v3
	neg-int v6, v8
	sub-int v91, v192, v205
	shl-long/2addr v9, v11
	xor-long v236, v37, v63
	mul-int/lit16 v9, v6, -14805
	shl-long v71, v184, v95
	int-to-double v2, v11
	add-float v248, v245, v105
	and-long v67, v146, v119
	add-int v156, v212, v17
	const-wide v3, 0x4df4795dbceda317L
	const-wide v5, 0xfc55e5c43200ab63L
	add-double/2addr v3, v5
	move/from16 v1, v245
	float-to-int v0, v1
	rem-double/2addr v5, v3
	ushr-int v227, v61, v123
	mul-double/2addr v5, v3
	mul-double/2addr v3, v5
	rem-int/lit16 v9, v0, 24888
	and-int/lit16 v6, v11, -30779
	xor-int/lit8 v91, v172, -73
	add-int/2addr v11, v8
	or-long/2addr v14, v12
	long-to-double v10, v12
	shr-long v217, v67, v240
	mul-int v229, v193, v74
	rem-int/lit8 v128, v201, 42
	xor-int/2addr v8, v6
	shr-int v171, v244, v48
	div-float v16, v24, v75
	sub-double/2addr v3, v10
	div-float v221, v248, v137
	double-to-float v2, v10
	add-long/2addr v14, v12
	add-long/2addr v12, v14
	neg-int v12, v6
	mul-long v12, v100, v116
	int-to-long v15, v8
	div-int/lit16 v12, v9, 10586
	ushr-long/2addr v15, v8
	move-wide/from16 v7, v263
	add-long/2addr v7, v15
	rem-int/lit16 v13, v6, 12778
	rem-float/2addr v1, v2
	add-int v255, v153, v125
	mul-double v97, v224, v93
	sub-int v243, v173, v207
	shr-long v169, v175, v201
	shr-long v65, v35, v12
	and-long v252, v234, v80
	sub-int v22, v135, v163
	rsub-int v0, v9, 6858
	add-int/lit16 v4, v9, -18485
	and-long/2addr v15, v7
	rem-float v248, v76, v2
	ushr-int v131, v51, v118
	sub-int v97, v153, v145
	xor-long/2addr v7, v15
	or-int/lit8 v9, v9, 68
	div-int/2addr v12, v9
	sub-long v180, v63, v150
	ushr-long v155, v100, v74
	xor-long v206, v178, v213
	add-int/lit8 v111, v12, 62
	or-long v116, v180, v65
	const-wide v1, 0xc43955494f1b07e8L
	div-double/2addr v1, v10
	rem-double v6, v40, v84
	xor-int/lit16 v6, v9, 24186
	add-int/lit16 v14, v12, -5059
	int-to-char v4, v14
	shr-long v161, v71, v163
	add-int/2addr v14, v9
	move/from16 v15, v103
	neg-float v5, v15
	div-float/2addr v15, v5
	and-int v157, v22, v6
	xor-int v144, v114, v89
	rem-int/lit8 v113, v51, 61
	const-wide v10, 0xa570de678675195cL
	const-wide v13, 0xdd3c8c38fba5670L
	const-wide v161, 256L
	or-long v10, v10, v161
	rem-long/2addr v13, v10
	sub-float v195, v15, v137
	shr-int/2addr v6, v0
	shl-int/2addr v0, v6
	double-to-int v10, v1
	sub-double v13, v224, v93
	add-int v118, v22, v167
	shl-int/2addr v0, v4
	add-int/lit8 v74, v201, -14
	div-int/lit16 v4, v6, -7935
	int-to-short v7, v6
	sub-int v103, v149, v205
	int-to-short v7, v9
	add-long v124, v26, v206
	shl-long v182, v252, v254
	mul-double v39, v54, v1
	shl-long v93, v206, v86
	ushr-int/lit8 v189, v189, 116
	rsub-int/lit8 v169, v126, -45
	xor-int v123, v189, v107
	or-int/lit16 v5, v10, 30561
	const-wide v0, 0xc55b91221127851fL
	const-wide v10, 0xbe88ce3cd38401c8L
	and-long/2addr v0, v10
	shl-long v102, v196, v128
	int-to-byte v0, v12
	or-int/lit8 v232, v232, 58
	rem-int v71, v130, v232
	const-wide v100, 1024L
	or-long v67, v67, v100
	div-long v132, v236, v67
	mul-int/2addr v6, v0
	int-to-byte v8, v0
	sub-double v8, v54, v13
	long-to-double v15, v10
	long-to-double v10, v10
	const v10, 0xb3fb24e7
	const v11, 0x60c858e0
	add-float/2addr v10, v11
	shr-long v209, v80, v136
	float-to-int v6, v10
	xor-long v96, v63, v150
	or-int/lit8 v122, v122, 109
	div-int v29, v48, v122
	or-int/lit8 v7, v7, 99
	div-int/2addr v5, v7
	shl-int/lit8 v171, v34, -9
	float-to-int v12, v11
	float-to-long v13, v11
	neg-double v6, v15
	shl-long v59, v252, v95
	xor-int/lit16 v13, v4, 7624
	int-to-double v8, v4
	float-to-double v2, v10
	sub-int/2addr v0, v5
	or-long v237, v30, v161
	const-wide v237, 131072L
	or-long v132, v132, v237
	div-long v176, v44, v132
	or-int/lit8 v212, v212, 83
	rem-int v9, v205, v212
	div-double v206, v230, v2
	neg-float v12, v11
	const-wide v4, 0xc6f9536c5003dfbdL
	move-wide/from16 v2, v267
	sub-long/2addr v4, v2
	sub-double v170, v54, v39
	rsub-int/lit8 v201, v17, -35
	xor-int/lit8 v109, v74, 38
	float-to-long v15, v12
	mul-int/lit8 v136, v223, 77
	rem-double v119, v206, v84
	add-long/2addr v15, v4
	double-to-float v11, v6
	xor-int/lit8 v10, v130, -80
	int-to-char v1, v13
	xor-int/lit16 v1, v9, -31944
	neg-int v10, v13
	ushr-int/lit8 v102, v227, -78
	long-to-float v1, v2
	xor-int/lit8 v189, v110, 90
	or-int/lit8 v246, v246, 51
	rem-int v46, v74, v246
	int-to-long v4, v9
	const-wide v7, 0xf42f21b229c0e2b4L
	const-wide v5, 0x60810f55ab9a5cdL
	add-double/2addr v5, v7
	add-int/lit16 v4, v10, -16317
	mul-int/lit16 v11, v13, 17524
	shl-int/lit8 v86, v28, -51
	sub-double v144, v54, v230
	double-to-long v0, v7
	rem-int/lit8 v41, v46, 90
	neg-long v14, v0
	or-int/2addr v9, v13
	rsub-int/lit8 v101, v254, 27
	add-long/2addr v2, v14
	ushr-int v229, v229, v149
	xor-long v2, v178, v146
	const v2, 0x964aeee1
	add-float/2addr v12, v2
	const-wide v37, 65536L
	or-long v14, v14, v37
	div-long/2addr v0, v14
	not-long v11, v0
	neg-float v7, v2
	shl-int/2addr v9, v13
	rem-double v159, v230, v119
	mul-float/2addr v2, v7
	double-to-long v13, v5
	rem-double v9, v39, v230
	sub-long/2addr v0, v11
	not-int v6, v4
	or-int/lit8 v6, v6, 24
	rem-int/2addr v4, v6
	or-int/2addr v6, v4
	shr-int/2addr v6, v4
	or-int/lit8 v4, v4, 14
	rem-int/2addr v6, v4
	const-wide v9, 0x5898ce75b87ce7bL
	const-wide v8, 0x6a046bc03d407466L
	move-wide/from16 v1, v39
	mul-double/2addr v1, v8
	float-to-long v11, v7
	const-wide v67, 134217728L
	or-long v176, v176, v67
	div-long v119, v234, v176
	sub-long v180, v213, v30
	rsub-int v2, v6, -29508
	and-int/2addr v4, v6
	long-to-int v5, v13
	and-int/lit16 v13, v5, 8308
	rem-double v56, v170, v39
	shr-long/2addr v11, v5
	int-to-byte v1, v4
	const-wide v35, 512L
	or-long v93, v93, v35
	rem-long v198, v213, v93
	mul-long v210, v198, v67
	long-to-float v13, v11
	int-to-byte v9, v2
	mul-int/2addr v6, v2
	div-float/2addr v7, v13
	and-int/lit8 v111, v77, 61
	const-wide v11, 0xfc5d45782c7aae71L
	double-to-int v10, v11
	shl-long v226, v176, v22
	move-wide/from16 v5, v182
	ushr-long/2addr v5, v4
	rsub-int/lit8 v17, v153, -65
	or-int/lit8 v10, v10, 85
	div-int/2addr v9, v10
	double-to-float v11, v11
	const-wide v4, 0xdaf5246e38338656L
	move-wide/from16 v15, v273
	rem-double/2addr v15, v4
	mul-float v19, v43, v248
	ushr-long v30, v161, v168
	ushr-int/2addr v10, v2
	div-double/2addr v4, v15
	rem-float/2addr v13, v7
	rsub-int/lit8 v47, v136, -30
	const-wide v5, 0xf7c69855686f93dfL
	long-to-double v1, v5
	not-int v4, v10
	mul-double/2addr v1, v15
	mul-float v100, v248, v43
	or-int/2addr v10, v9
	float-to-int v6, v7
	shr-int/lit8 v37, v101, -82
	rem-int/lit16 v15, v9, -29653
	rem-float v234, v158, v221
	mul-float v128, v13, v76
	add-float v153, v43, v234
	mul-double v113, v230, v144
	rem-int/lit8 v225, v167, -28
	xor-long v64, v237, v63
	div-float v146, v100, v158
	int-to-double v1, v15
	const-wide v8, 0x8b1054d93625dad2L
	rem-double/2addr v8, v1
	sub-float/2addr v7, v13
	and-long v19, v132, v217
	sub-double/2addr v8, v1
	const-wide v155, 131072L
	or-long v180, v180, v155
	rem-long v88, v161, v180
	mul-double/2addr v1, v8
	and-int/lit16 v8, v6, -16278
	rem-double v224, v54, v1
	sub-int v225, v87, v244
	shr-long v113, v88, v33
	xor-int v118, v18, v6
	rsub-int/lit8 v190, v172, 85
	rem-float/2addr v11, v7
	const-wide v5, 0xe91b71f6cee02f37L
	shr-long/2addr v5, v8
	add-int v251, v225, v10
	long-to-double v8, v5
	long-to-double v6, v5
	or-long v146, v132, v180
	add-double v246, v159, v8
	const-wide v96, 8388608L
	or-long v44, v44, v96
	div-long v143, v180, v44
	and-int/lit8 v222, v28, -126
	ushr-long v229, v59, v163
	xor-long v134, v176, v124
	int-to-short v12, v15
	double-to-int v13, v8
	const-wide v1, 0x145cc05facc0ba69L
	const-wide v0, 0x615b7350dd1a99deL
	move-wide/from16 v15, v132
	and-long/2addr v15, v0
	ushr-long v127, v210, v203
	ushr-long/2addr v15, v4
	rem-double/2addr v8, v6
	shl-int/2addr v12, v4
	double-to-float v4, v6
	or-int/lit8 v169, v131, 69
	or-long/2addr v15, v0
	mul-int/2addr v10, v12
	sub-double v3, v54, v84
	add-int v52, v172, v107
	sub-long v102, v184, v146
	and-int/lit8 v134, v48, 75
	add-float v168, v76, v234
	const v11, 0xcca72982
	const v3, 0x9925c71e
	mul-float/2addr v3, v11
	ushr-int/lit8 v107, v51, -125
	mul-long/2addr v15, v0
	rem-int/lit16 v8, v12, -6718
	div-double v35, v39, v84
	xor-int/lit16 v6, v8, -26377
	rem-double v59, v39, v56
	not-long v11, v0
	mul-int/2addr v13, v10
	xor-long v69, v143, v96
	const-wide v1, 0xc7522bed9cd207f4L
	const-wide v15, 0x1be9ac5e3f8c8133L
	add-double/2addr v15, v1
	sub-int/2addr v6, v13
	add-int/lit8 v159, v107, -30
	add-int/lit8 v153, v139, -72
	rem-double/2addr v1, v15
	or-int/lit8 v110, v159, -31
	shr-int/2addr v6, v8
	long-to-int v12, v11
	shr-int/lit8 v95, v71, -109
	const-wide v13, 0xe397137e4ef90b4aL
	not-long v11, v13
	const v14, 0xb1eb2373
	div-float/2addr v3, v14
	or-long v135, v143, v146
	not-int v13, v10
	const-wide v11, 0x33e2c9722713c31eL
	const-wide v9, 0x91099ad0795ebf85L
	or-long/2addr v11, v9
	sub-int v172, v123, v200
	div-float/2addr v3, v14
	rem-float/2addr v3, v14
	long-to-float v9, v11
	mul-long v150, v213, v237
	float-to-int v1, v14
	div-int/lit16 v11, v8, 1243
	const-wide v3, 0xbbde9c78d8cdef8fL
	ushr-long/2addr v3, v13
	xor-int v40, v172, v194
	int-to-double v4, v13
	move-wide/from16 v10, v180
	const-wide v3, 0x3ca0e95eacd7e9efL
	const-wide v30, 524288L
	or-long v10, v10, v30
	rem-long/2addr v3, v10
	mul-float v146, v76, v14
	move-wide/from16 v12, v206
	rem-double/2addr v12, v15
	rem-double/2addr v12, v15
	xor-int/lit16 v11, v6, 19294
	float-to-long v13, v9
	div-int/lit8 v239, v40, 127
	and-int/lit16 v4, v8, -16651
	const-wide v9, 0xb8d50375684b033aL
	sub-double/2addr v15, v9
	const-wide v11, 0x640356ee639929c5L
	xor-long/2addr v13, v11
	rsub-int v13, v8, -17670
	add-long v145, v102, v237
	shl-long/2addr v11, v6
	mul-int/lit8 v191, v194, 107
	rem-float v197, v100, v221
	rem-int/lit16 v15, v4, 21591
	double-to-long v1, v9
	int-to-char v4, v8
	mul-double v193, v9, v54
	add-int v29, v52, v134
	xor-int/lit16 v2, v4, 20593
	const-wide v5, 0x8ae96d1a7013173dL
	or-long/2addr v5, v11
	shr-int v167, v50, v167
	long-to-double v12, v11
	int-to-float v11, v15
	sub-float v42, v248, v234
	sub-int/2addr v15, v8
	or-int/lit8 v189, v244, -128
	and-int v98, v107, v86
	mul-double v180, v84, v56
	ushr-int/lit8 v52, v87, 44
	const v4, 0x8389cb20
	add-float/2addr v4, v11
	mul-int/lit16 v11, v15, 13798
	and-int/lit16 v2, v15, -6001
	shl-long v26, v184, v212
	mul-int/2addr v8, v2
	mul-double v59, v9, v12
	not-int v3, v2
	int-to-float v2, v3
	rsub-int/lit8 v116, v169, 94
	const-wide v7, 0x549750da1407f8c7L
	and-long/2addr v7, v5
	or-int/lit8 v15, v15, 116
	rem-int/2addr v3, v15
	int-to-char v14, v3
	rsub-int/lit8 v121, v131, -79
	shr-int/lit8 v175, v116, 66
	div-int/lit8 v117, v130, -8
	and-int/lit8 v10, v3, -86
	and-int/lit16 v13, v14, -8078
	shl-int v62, v101, v222
	ushr-int/2addr v15, v3
	neg-int v13, v14
	const-wide v10, 0x5c098940066be4b9L
	move-wide/from16 v14, v269
	div-double/2addr v10, v14
	and-int/2addr v13, v3
	ushr-int v125, v254, v191
	ushr-int/lit8 v160, v212, -30
	shl-int/2addr v3, v13
	xor-int/lit16 v13, v3, 6698
	ushr-int/2addr v13, v3
	neg-long v11, v7
	or-int/lit8 v87, v87, 42
	div-int v117, v47, v87
	const-wide v14, 0xfaff15921e9a5df7L
	const-wide v2, 0x54b36ed9777a0667L
	sub-double/2addr v2, v14
	add-double v219, v246, v35
	shr-long v143, v113, v126
	add-double v86, v35, v14
	rsub-int v2, v13, 8990
	or-int/lit8 v69, v51, -97
	sub-long/2addr v7, v11
	mul-int/lit8 v250, v46, 35
	int-to-long v9, v13
	int-to-char v9, v2
	div-double v177, v59, v193
	int-to-double v10, v2
	int-to-long v8, v9
	sub-long v66, v161, v252
	shl-int/lit8 v44, v2, -112
	long-to-float v1, v5
	not-int v1, v13
	xor-int/2addr v13, v1
	mul-double/2addr v14, v10
	long-to-float v10, v8
	or-long v246, v93, v150
	int-to-char v6, v1
	mul-int/lit16 v5, v13, -20947
	add-float v34, v75, v234
	or-int v61, v167, v13
	move-wide/from16 v10, v64
	const-wide v135, 4L
	or-long v8, v8, v135
	div-long/2addr v10, v8
	const-wide v0, 0xe183d9091b2428acL
	add-double/2addr v0, v14
	sub-double/2addr v0, v14
	and-int/2addr v2, v6
	div-int/lit8 v166, v90, 91
	div-float v43, v168, v75
	double-to-int v10, v14
	shl-long/2addr v8, v6
	const-wide v13, 0x4502e7a76d9f0f01L
	sub-long/2addr v13, v8
	mul-long/2addr v13, v8
	rem-int/lit16 v11, v10, -22249
	rem-float v178, v34, v4
	mul-int v64, v61, v107
	const-wide v15, 0x843c316ddc39ca53L
	rem-double/2addr v15, v0
	int-to-float v13, v5
	div-float v207, v245, v43
	mul-float/2addr v4, v13
	move-wide/from16 v6, v252
	const-wide v226, 8192L
	or-long v6, v6, v226
	rem-long/2addr v8, v6
	add-float/2addr v13, v4
	int-to-float v6, v11
	const-wide v15, 0x6fd9991cc8d90fefL
	and-long/2addr v8, v15
	shl-int/2addr v5, v11
	ushr-int v103, v62, v10
	add-long/2addr v15, v8
	rem-float/2addr v13, v4
	add-int/lit16 v14, v10, -4743
	float-to-double v7, v13
	float-to-double v0, v6
	double-to-float v6, v7
	ushr-int/2addr v2, v11
	rsub-int/lit8 v13, v251, 87
	shl-int v243, v200, v134
	float-to-int v15, v4
	const-wide v7, 0x2638e4a277d37f8cL
	long-to-double v4, v7
	neg-double v14, v4
	div-float v16, v24, v137
	const-wide v93, 131072L
	or-long v19, v19, v93
	div-long v214, v217, v19
	add-int/lit8 v203, v95, -11
	and-int/2addr v11, v10
	double-to-int v9, v0
	float-to-double v2, v6
	ushr-long/2addr v7, v13
	add-int/lit8 v237, v165, -35
	or-int/lit8 v103, v103, 45
	rem-int v115, v237, v103
	neg-double v3, v4
	mul-float v139, v16, v42
	or-int v25, v140, v18
	ushr-int/lit8 v178, v28, 66
	add-int v171, v173, v115
	mul-long v228, v96, v93
	long-to-float v2, v7
	long-to-int v12, v7
	and-int/lit8 v208, v167, 118
	neg-long v8, v7
	const-wide v3, 0xe80a09b8c3924b02L
	sub-long/2addr v3, v8
	int-to-byte v4, v11
	and-int v135, v71, v95
	rem-int/lit8 v92, v108, -76
	not-int v2, v11
	div-int/lit8 v154, v111, -29
	or-int/lit8 v13, v13, 60
	rem-int/2addr v10, v13
	int-to-double v2, v2
	shl-int v74, v13, v223
	float-to-int v3, v6
	and-int/2addr v11, v10
	or-int/2addr v4, v13
	sub-float v18, v245, v6
	not-long v7, v8
	sub-int v84, v17, v154
	add-int/lit8 v61, v175, -27
	long-to-int v11, v7
	sub-double v172, v219, v14
	long-to-int v14, v7
	rsub-int v7, v14, -22747
	shl-int v64, v7, v232
	shl-long v223, v80, v47
	sub-double v195, v219, v59
	ushr-int v222, v37, v112
	div-double v80, v86, v193
	mul-int v200, v203, v47
	mul-int/2addr v7, v4
	shl-int/2addr v13, v12
	xor-int/2addr v3, v14
	or-int/lit16 v13, v12, -24907
	const-wide v14, 0x82b8d1018364c357L
	const-wide v2, 0xb75dab7c0624cb76L
	and-long/2addr v2, v14
	neg-float v9, v6
	shl-int/2addr v12, v11
	const-wide v12, 0x150fcab621d52776L
	add-double/2addr v0, v12
	int-to-float v0, v4
	const-wide v66, 524288L
	or-long v26, v26, v66
	div-long v28, v82, v26
	int-to-byte v10, v4
	shr-int/2addr v10, v4
	long-to-double v1, v14
	int-to-short v0, v7
	mul-int v10, v47, v201
	shr-long v114, v228, v165
	rsub-int v5, v7, 17784
	rem-float/2addr v9, v6
	or-int v141, v25, v130
	neg-float v6, v6
	const-wide v150, 2097152L
	or-long v93, v93, v150
	div-long v139, v26, v93
	add-double v183, v1, v172
	and-long v125, v26, v217
	long-to-float v9, v14
	const-wide v1, 0xdd57106f73b13a51L
	const-wide v28, 33554432L
	or-long v1, v1, v28
	rem-long/2addr v14, v1
	or-int/lit8 v225, v225, 34
	rem-int v40, v74, v225
	add-int/lit8 v52, v200, 58
	div-float v159, v248, v245
	add-long/2addr v14, v1
	rem-float/2addr v6, v9
	rem-int/lit16 v7, v0, 3139
	div-float/2addr v9, v6
	shl-long/2addr v14, v7
	or-long/2addr v1, v14
	mul-long v59, v246, v223
	shr-int v243, v98, v154
	ushr-int v97, v122, v149
	rsub-int/lit8 v227, v169, -122
	int-to-short v8, v11
	rem-float v40, v105, v207
	mul-float v171, v158, v42
	neg-double v4, v12
	long-to-double v11, v1
	shr-long/2addr v14, v0
	shr-int/2addr v7, v0
	not-int v11, v0
	add-double v46, v4, v80
	const-wide v2, 0xed90e1c394efcbf1L
	div-double/2addr v2, v4
	div-double v234, v193, v195
	double-to-float v6, v4
	xor-int v3, v208, v0
	xor-int/lit8 v133, v251, 106
	mul-double v173, v54, v46
	rem-int/lit8 v69, v244, -119
	xor-int/lit16 v13, v10, 20266
	const-wide v4, 0x226ca23156bc7309L
	mul-long/2addr v4, v14
	or-int/lit8 v255, v255, 9
	rem-int v191, v203, v255
	or-long v183, v139, v214
	mul-float/2addr v9, v6
	rsub-int v15, v11, -7646
	const-wide v1, 0x2d4d6506703b1f2L
	double-to-int v9, v1
	shr-long v13, v127, v25
	float-to-int v0, v6
	mul-long v108, v13, v93
	mul-float v23, v18, v197
	shl-long v211, v150, v227
	const v2, 0xd70ec9d3
	add-float/2addr v6, v2
	mul-int v20, v167, v141
	ushr-int v151, v154, v200
	xor-int/2addr v11, v8
	rem-int/lit16 v10, v3, 24832
	ushr-long v148, v30, v134
	const-wide v13, 0xf462e86236073e60L
	const-wide v14, 0xd28bf2e79c24c0f7L
	const-wide v6, 0xde2a9cacef5d997fL
	div-double/2addr v14, v6
	shl-int/lit8 v235, v98, 58
	add-long v56, v82, v183
	const v8, 0x54b91d9e
	sub-float/2addr v2, v8
	sub-double/2addr v14, v6
	shr-int v0, v74, v123
	int-to-byte v5, v3
	sub-long v68, v88, v114
	xor-int/2addr v5, v9
	or-int v112, v111, v130
	const-wide v0, 0x28ff929160b01f54L
	const-wide v4, 0x5a56fae7ecbc0bd0L
	mul-long/2addr v4, v0
	mul-double v186, v46, v35
	long-to-int v11, v0
	or-int/lit8 v72, v111, 12
	int-to-double v13, v9
	xor-long/2addr v0, v4
	ushr-long v140, v223, v192
	const-wide v228, 4096L
	or-long v0, v0, v228
	rem-long/2addr v4, v0
	not-long v13, v0
	shl-long/2addr v4, v9
	and-long v234, v0, v59
	or-int/lit8 v237, v237, 125
	rem-int v190, v201, v237
	ushr-int v191, v92, v244
	shl-int v178, v250, v191
	neg-int v5, v11
	shr-int/lit8 v198, v91, 40
	and-int/lit16 v13, v3, -6579
	const-wide v8, 0x962d85622d4b4b83L
	xor-long/2addr v0, v8
	mul-long v243, v217, v88
	shl-long v209, v145, v201
	rem-int/lit8 v132, v92, 102
	sub-long v186, v26, v217
	int-to-char v11, v5
	const v5, 0x94aa74c1
	div-float/2addr v2, v5
	neg-double v7, v6
	rsub-int/lit8 v87, v98, -9
	sub-float v27, v2, v100
	or-long v48, v0, v59
	mul-double v99, v195, v46
	xor-int/lit8 v237, v97, -21
	add-float/2addr v5, v2
	shr-int v175, v87, v90
	and-int/lit16 v1, v13, 5806
	neg-int v11, v11
	xor-int/lit16 v0, v1, 9907
	shr-int/2addr v13, v10
	ushr-long v207, v155, v225
	mul-int v116, v51, v239
	rem-float/2addr v5, v2
	xor-int/2addr v10, v3
	ushr-int/lit8 v93, v130, -81
	add-int/lit16 v12, v3, -14815
	mul-int/2addr v0, v1
	int-to-char v14, v3
	ushr-int/2addr v3, v12
	or-int/lit16 v0, v11, 24848
	const-wide v3, 0xfe5b40748658a233L
	move-wide/from16 v12, v88
	const-wide v183, 4194304L
	or-long v3, v3, v183
	div-long/2addr v12, v3
	xor-int/lit8 v76, v189, -27
	int-to-byte v4, v1
	double-to-float v14, v7
	const-wide v3, 0x1a7c57b7640f277dL
	div-double/2addr v3, v7
	add-double v210, v219, v35
	const-wide v4, 0xfe14964b85ecb26eL
	and-long/2addr v4, v12
	const-wide v246, 4096L
	or-long v140, v140, v246
	div-long v63, v56, v140
	div-int/lit8 v76, v130, -117
	shr-int/lit8 v39, v20, 115
	shl-long/2addr v4, v10
	or-int/lit8 v87, v87, 73
	div-int v28, v116, v87
	long-to-double v11, v4
	rsub-int/lit8 v52, v132, 7
	float-to-long v3, v2
	and-int/lit16 v7, v0, 12004
	add-int v202, v39, v251
	float-to-double v7, v14
	mul-int/lit8 v202, v62, -10
	or-int/lit16 v10, v10, -17589
	add-int/lit16 v1, v0, 12578
	ushr-long/2addr v3, v1
	move-wide/from16 v6, v207
	const-wide v243, 16384L
	or-long v6, v6, v243
	rem-long/2addr v3, v6
	shl-int/2addr v0, v10
	add-long/2addr v6, v3
	or-int/lit8 v10, v10, 37
	rem-int/2addr v0, v10
	not-long v11, v6
	long-to-float v12, v6
	xor-int/lit8 v217, v51, -7
	neg-int v8, v1
	const-wide v5, 0x3177ad9c94a43cd9L
	neg-double v0, v5
	or-int/lit8 v8, v8, 3
	rem-int/2addr v10, v8
	div-int/lit16 v4, v8, -21703
	or-int/lit16 v7, v10, -1966
	and-int/lit8 v143, v101, -128
	div-double/2addr v0, v5
	sub-int/2addr v10, v7
	const-wide v4, 0x74f4885bc36e2635L
	const-wide v8, 0xdb341c684b5d9817L
	const-wide v88, 64L
	or-long v8, v8, v88
	rem-long/2addr v4, v8
	rsub-int v4, v10, -20980
	add-int/2addr v10, v7
	long-to-double v11, v8
	shl-long v36, v183, v20
	mul-float v2, v248, v34
	and-int/lit8 v222, v135, -108
	xor-int/lit8 v165, v122, -34
	rem-double/2addr v0, v11
	ushr-int v149, v227, v76
	xor-int/lit8 v17, v74, 111
	move-wide/from16 v13, v30
	sub-long/2addr v8, v13
	mul-long/2addr v8, v13
	shl-long v1, v114, v74
	or-int/lit16 v10, v7, -15994
	move-wide/from16 v2, v271
	rem-double/2addr v2, v11
	shr-long/2addr v13, v7
	and-long/2addr v8, v13
	add-int/lit8 v22, v251, -103
	xor-int/2addr v10, v4
	mul-int/2addr v4, v7
	int-to-double v12, v10
	const v0, 0x6b27b08e
	const v15, 0x88a9c4a5
	add-float/2addr v15, v0
	not-int v9, v7
	shl-int/lit8 v147, v200, -38
	sub-double/2addr v12, v2
	rem-double v240, v210, v54
	const-wide v8, 0x9ecfd21a069a2211L
	shl-long/2addr v8, v7
	ushr-long v99, v8, v160
	add-int/lit16 v12, v10, -7968
	const-wide v6, 0xa5f901c8798aae81L
	const-wide v223, 8388608L
	or-long v6, v6, v223
	rem-long/2addr v8, v6
	move-wide/from16 v8, v193
	add-double/2addr v8, v2
	div-int/lit16 v5, v12, 20132
	sub-double v229, v2, v195
	float-to-int v8, v15
	add-int v207, v41, v251
	add-int v115, v227, v239
	or-int/lit16 v9, v10, 6063
	int-to-long v1, v10
	and-long v140, v234, v214
	rsub-int v1, v12, 16691
	or-int/lit8 v5, v5, 72
	div-int/2addr v1, v5
	mul-double v140, v193, v80
	shl-int/lit8 v96, v117, 120
	or-long v246, v66, v48
	and-int/2addr v8, v1
	int-to-short v0, v1
	shl-int/2addr v12, v4
	div-double v100, v193, v210
	and-int v253, v191, v250
	int-to-short v12, v12
	rem-int/lit16 v11, v5, 15166
	const-wide v1, 0x8916a3e81c7f4db3L
	const-wide v7, 0x99b70c48edb8aaeL
	div-double/2addr v7, v1
	ushr-int/2addr v4, v12
	move-wide/from16 v2, v246
	shr-long/2addr v2, v11
	const v12, 0x16086584
	add-float/2addr v12, v15
	shr-int/2addr v4, v10
	ushr-long/2addr v2, v5
	or-int/lit8 v147, v147, 66
	div-int v235, v5, v147
	and-int v252, v62, v107
	const-wide v7, 0x508280698b485434L
	const-wide v12, 0x148fc31a487d5445L
	rem-double/2addr v12, v7
	const-wide v12, 0xb8500ff5c9360febL
	sub-long/2addr v2, v12
	xor-int v111, v200, v190
	const-wide v10, 0xdaa98ded4e0aa91cL
	add-double/2addr v7, v10
	int-to-byte v1, v0
	neg-float v4, v15
	div-float/2addr v4, v15
	sub-float v58, v27, v24
	xor-long v165, v223, v246
	add-double v148, v80, v173
	and-int/lit16 v8, v1, 1633
	sub-float/2addr v15, v4
	not-int v2, v5
	xor-long v22, v165, v214
	mul-int/lit16 v0, v8, -23427
	or-long v125, v161, v214
	sub-long v50, v243, v48
	float-to-int v5, v15
	shr-long/2addr v12, v1
	mul-int/lit8 v43, v207, -33
	div-float/2addr v15, v4
	ushr-int/2addr v9, v0
	const-wide v2, 0x1760cb732d50a0f0L
	add-double/2addr v2, v10
	sub-int/2addr v0, v5
	add-int/2addr v9, v1
	sub-float v190, v18, v34
	rsub-int v3, v1, 11918
	and-int/lit8 v189, v110, -89
	shr-long/2addr v12, v9
	xor-int/lit8 v58, v201, -7
	ushr-int/2addr v8, v9
	xor-int/2addr v3, v5
	shl-int/2addr v8, v5
	rem-int/lit8 v97, v235, 4
	mul-float v5, v24, v245
	add-float/2addr v15, v5
	xor-long v33, v12, v59
	int-to-float v8, v0
	shl-long/2addr v12, v0
	xor-int/lit8 v157, v90, 10
	add-float v101, v105, v75
	div-int/lit16 v11, v0, -32544
	move-wide/from16 v14, v267
	and-long/2addr v14, v12
	ushr-int/2addr v1, v0
	long-to-float v15, v14
	or-int/lit8 v11, v11, 69
	div-int/2addr v9, v11
	long-to-float v9, v12
	xor-int/lit8 v119, v112, -113
	div-int/lit16 v9, v0, -18224
	mul-int/2addr v9, v3
	const-wide v30, 32768L
	or-long v145, v145, v30
	div-long v49, v108, v145
	xor-int v60, v239, v254
	move-wide/from16 v4, v243
	sub-long/2addr v4, v12
	and-long/2addr v12, v4
	mul-long/2addr v4, v12
	sub-double v16, v46, v148
	sub-long/2addr v12, v4
	not-long v11, v4
	rsub-int v11, v3, -24338
	rem-float/2addr v15, v8
	sub-int v158, v254, v157
	shr-int v181, v217, v157
	shr-int/lit8 v130, v41, -53
	const-wide v1, 0xb9ab36d8bc5ef695L
	add-long/2addr v1, v4
	move-wide/from16 v1, v54
	double-to-float v6, v1
	xor-int v150, v154, v95
	not-int v13, v0
	const-wide v11, 0xa42e88fa3f2f7d54L
	const-wide v243, 1024L
	or-long v11, v11, v243
	div-long/2addr v4, v11
	shr-int v33, v203, v150
	ushr-int/2addr v0, v3
	rem-int/lit8 v215, v153, -40
	rsub-int v8, v9, 26174
	sub-int v232, v192, v3
	add-float/2addr v6, v15
	not-long v2, v11
	const-wide v12, 0xbd34ac9fd70fdc41L
	double-to-float v10, v12
	rem-float v101, v137, v171
	neg-long v7, v2
	int-to-byte v8, v9
	shl-long v158, v49, v131
	mul-double v88, v46, v12
	const-wide v108, 33554432L
	or-long v82, v82, v108
	div-long v201, v243, v82
	or-int/lit8 v132, v132, 82
	div-int v116, v20, v132
	long-to-double v7, v2
	float-to-long v2, v10
	or-int/lit8 v136, v61, 27
	const-wide v183, 262144L
	or-long v161, v161, v183
	rem-long v7, v2, v161
	xor-int/2addr v9, v0
	const-wide v125, 268435456L
	or-long v2, v2, v125
	div-long/2addr v4, v2
	int-to-byte v2, v0
	rsub-int/lit8 v84, v41, 23
	shl-int/lit8 v1, v115, 24
	ushr-int/2addr v2, v9
	and-int/lit16 v1, v1, 1661
	ushr-int/lit8 v228, v222, 49
	long-to-double v0, v7
	double-to-long v11, v12
	shr-int/2addr v9, v2
	mul-float v17, v75, v42
	rem-int/lit16 v8, v9, -12902
	div-float v53, v24, v10
	sub-int/2addr v2, v9
	ushr-int v82, v8, v107
	add-double v144, v229, v219
	add-float/2addr v10, v6
	mul-double v92, v210, v173
	or-int/lit8 v9, v9, 37
	div-int/2addr v2, v9
	long-to-double v9, v4
	shr-long v51, v108, v133
	neg-int v4, v8
	long-to-float v2, v11
	mul-int/2addr v4, v8
	shl-int v108, v200, v25
	mul-int v181, v131, v82
	add-float/2addr v2, v6
	const-wide v125, 33554432L
	or-long v49, v49, v125
	rem-long v216, v186, v49
	rem-float v226, v168, v245
	mul-int/lit8 v36, v227, 73
	rem-double v129, v80, v9
	sub-int/2addr v4, v8
	rem-double v229, v240, v92
	const-wide v186, 4194304L
	or-long v63, v63, v186
	rem-long v230, v161, v63
	or-int/lit16 v14, v4, 5988
	add-double v39, v140, v129
	add-float v160, v190, v2
	float-to-long v2, v15
	const-wide v68, 2L
	or-long v2, v2, v68
	div-long/2addr v11, v2
	int-to-byte v15, v8
	rsub-int v7, v14, -22790
	int-to-short v2, v7
	float-to-int v6, v6
	div-double v224, v46, v54
	move/from16 v6, v24
	move/from16 v0, v248
	sub-float/2addr v6, v0
	rsub-int/lit8 v145, v96, -58
	div-int/lit8 v132, v145, 87
	const-wide v2, 0x430ba6c897979878L
	div-double/2addr v9, v2
	and-long v107, v63, v127
	shl-int v20, v8, v239
	and-int/2addr v14, v8
	or-long v110, v30, v186
	mul-int/lit8 v51, v74, -63
	mul-double v137, v148, v193
	or-int/lit16 v12, v14, -15547
	rem-int/lit8 v128, v72, 43
	div-int/lit8 v153, v97, -46
	move-wide/from16 v11, v263
	const-wide v0, 0xf8d940efa6527caL
	sub-long/2addr v11, v0
	xor-int/lit8 v75, v116, -86
	neg-int v1, v8
	shl-long/2addr v11, v8
	long-to-double v12, v11
	const-wide v230, 2L
	or-long v161, v161, v230
	rem-long v127, v201, v161
	float-to-double v8, v6
	mul-float v163, v17, v226
	ushr-int/lit8 v63, v44, 17
	const-wide v6, 0x50d80989dfbab011L
	shl-long/2addr v6, v1
	rem-double/2addr v2, v12
	move-wide/from16 v9, v49
	const-wide v30, 1073741824L
	or-long v6, v6, v30
	rem-long/2addr v9, v6
	xor-int/lit8 v98, v51, -7
	const-wide v125, 8192L
	or-long v6, v6, v125
	div-long/2addr v9, v6
	mul-int/lit16 v15, v4, 26179
	add-int/lit8 v62, v112, 32
	shl-long v122, v158, v74
	const-wide v30, 1024L
	or-long v66, v66, v30
	div-long v179, v110, v66
	xor-int/lit16 v15, v15, 9883
	const v15, 0x7fd3f6ee
	const v10, 0xa25cd299
	mul-float/2addr v15, v10
	or-int v163, v154, v191
	move-wide/from16 v2, v49
	or-long/2addr v6, v2
	const-wide v107, 16L
	or-long v68, v68, v107
	rem-long v208, v201, v68
	add-int v207, v192, v43
	shl-long/2addr v6, v4
	mul-long/2addr v6, v2
	xor-long/2addr v2, v6
	long-to-int v1, v6
	rsub-int/lit8 v221, v4, -123
	float-to-double v2, v15
	float-to-long v14, v15
	const-wide v6, 128L
	or-long v14, v14, v6
	rem-long/2addr v6, v14
	const-wide v186, 536870912L
	or-long v183, v183, v186
	div-long v211, v14, v183
	float-to-double v2, v10
	or-long v100, v30, v161
	xor-int v28, v91, v135
	shl-long v129, v158, v136
	div-float v163, v53, v245
	add-float v31, v160, v226
	const-wide v14, 16384L
	or-long v155, v155, v14
	rem-long v50, v122, v155
	mul-long v198, v216, v122
	mul-float v85, v168, v17
	const v12, 0xe0865736
	mul-float/2addr v12, v10
	rem-int/lit16 v8, v4, -9674
	sub-float v177, v27, v197
	mul-int/2addr v4, v1
	and-int/2addr v1, v8
	or-int v169, v253, v135
	or-int/lit8 v4, v4, 87
	rem-int/2addr v8, v4
	rem-float/2addr v12, v10
	neg-double v7, v2
	rem-int/lit8 v19, v97, 121
	xor-int/lit8 v181, v61, 57
	shl-int/2addr v4, v1
	sub-double/2addr v2, v7
	add-double/2addr v2, v7
	rem-double/2addr v2, v7
	move-wide/from16 v12, v110
	const-wide v50, 1073741824L
	or-long v12, v12, v50
	div-long/2addr v14, v12
	rem-int/lit8 v153, v61, -96
	or-int/lit8 v235, v235, 69
	rem-int v103, v157, v235
	int-to-double v2, v1
	int-to-short v0, v1
	int-to-long v5, v4
	shr-int/lit8 v255, v112, -87
	sub-float v140, v85, v171
	div-double v219, v193, v137
	const-wide v22, 4096L
	or-long v208, v208, v22
	rem-long v146, v127, v208
	add-long v175, v56, v198
	sub-float v210, v163, v31
	rem-float v16, v17, v210
	const v0, 0xe262c95
	sub-float/2addr v0, v10
	sub-float v200, v210, v171
	rem-int/lit16 v1, v1, -20465
	add-int/lit8 v115, v143, 11
	sub-double v7, v193, v137
	or-int/lit8 v4, v4, 16
	div-int/2addr v1, v4
	float-to-double v1, v0
	sub-long/2addr v14, v5
	sub-float/2addr v0, v10
	or-int/lit8 v229, v221, -82
	or-int/lit16 v13, v4, -15674
	add-long/2addr v14, v5
	xor-long/2addr v14, v5
	int-to-long v2, v13
	add-int/lit16 v3, v13, -15536
	const-wide v100, 268435456L
	or-long v183, v183, v100
	div-long v223, v216, v183
	shl-long v215, v56, v3
	double-to-int v6, v7
	rem-float/2addr v10, v0
	add-long v108, v243, v125
	long-to-int v0, v14
	mul-int/2addr v6, v3
	long-to-float v5, v14
	neg-long v15, v14
	int-to-char v13, v13
	sub-long v32, v175, v129
	rem-float/2addr v10, v5
	int-to-char v8, v3
	move-wide/from16 v12, v269
	double-to-float v13, v12
	shr-long/2addr v15, v6
	mul-int/lit8 v168, v72, 50
	rem-float/2addr v5, v13
	float-to-double v8, v10
	const-wide v11, 0x10cd9152bff727bdL
	rem-double/2addr v8, v11
	mul-float/2addr v13, v5
	or-int/lit8 v235, v235, 7
	div-int v170, v76, v235
	const-wide v6, 0x24c883c6b651b758L
	add-long/2addr v6, v15
	and-long/2addr v6, v15
	sub-long v11, v146, v100
	long-to-int v7, v15
	const-wide v15, 67108864L
	or-long v11, v11, v15
	div-long/2addr v15, v11
	shr-int/lit8 v253, v143, 49
	mul-float/2addr v5, v13
	rem-int/lit8 v43, v157, 45
	long-to-int v7, v11
	or-int/lit8 v72, v72, 42
	rem-int v194, v178, v72
	sub-long v166, v32, v165
	xor-int/2addr v3, v0
	const-wide v215, 8L
	or-long v15, v15, v215
	rem-long/2addr v11, v15
	shr-long/2addr v11, v4
	rsub-int v0, v7, 28344
	const-wide v13, 0xaf558231d40dbf8dL
	add-double/2addr v8, v13
	sub-double/2addr v8, v13
	or-int/2addr v3, v4
	sub-long v147, v110, v186
	rem-float/2addr v10, v5
	or-int v251, v239, v251
	shr-int v186, v235, v4
	neg-long v8, v15
	or-int/lit8 v206, v60, -112
	const-wide v0, 0x4e900d670847a868L
	add-double/2addr v0, v13
	sub-int v28, v154, v115
	add-int/lit8 v120, v19, 125
	mul-double/2addr v13, v0
	float-to-long v15, v5
	mul-int/2addr v7, v3
	const-wide v230, 2L
	or-long v11, v11, v230
	div-long/2addr v15, v11
	div-int/lit8 v250, v253, -63
	ushr-long/2addr v8, v3
	or-int/2addr v4, v3
	div-double v248, v137, v46
	and-long v13, v50, v246
	shr-int v219, v221, v205
	neg-long v15, v15
	const-wide v5, 0x761145f2b68bb0f0L
	mul-double/2addr v5, v0
	move/from16 v2, v17
	sub-float/2addr v10, v2
	mul-int/lit8 v164, v96, -113
	and-int v204, v132, v43
	and-int v29, v84, v181
	mul-int v108, v157, v112
	sub-double v244, v46, v248
	int-to-float v11, v7
	float-to-long v15, v10
	rem-double v216, v88, v0
	add-int/lit8 v169, v153, 75
	and-int/2addr v3, v4
	sub-double/2addr v0, v5
	int-to-double v2, v4
	sub-long/2addr v15, v13
	double-to-long v11, v5
	mul-double/2addr v2, v5
	mul-long v21, v11, v127
	float-to-long v9, v10
	or-int v54, v178, v7
	sub-int v121, v153, v192
	double-to-long v8, v2
	div-int/lit8 v54, v97, -84
	sub-long v50, v158, v21
	xor-int/lit8 v223, v90, 5
	int-to-short v11, v7
	shl-int/2addr v4, v7
	neg-long v3, v15
	or-int/lit8 v192, v7, -119
	long-to-double v9, v3
	add-int/lit8 v219, v98, -13
	const v12, 0xd253a7de
	float-to-long v13, v12
	ushr-long/2addr v15, v11
	move/from16 v13, v190
	mul-float/2addr v12, v13
	sub-float v171, v226, v42
	int-to-long v12, v11
	const-wide v161, 33554432L
	or-long v12, v12, v161
	rem-long v235, v100, v12
	sub-float v175, v17, v140
	not-long v3, v12
	shl-long/2addr v3, v11
	rem-int/lit16 v14, v11, 13117
	sub-float v152, v160, v140
	add-long/2addr v15, v12
	add-double v88, v80, v39
	mul-long v3, v208, v66
	or-long/2addr v3, v15
	or-int/2addr v14, v11
	long-to-float v11, v3
	sub-long v144, v3, v211
	or-long v203, v110, v32
	div-float v58, v27, v197
	neg-int v14, v14
	or-int/lit8 v170, v20, -128
	shl-long/2addr v15, v14
	mul-long v226, v66, v179
	ushr-int/lit8 v15, v250, -102
	neg-long v9, v12
	div-int/lit8 v152, v168, 53
	mul-long/2addr v9, v12
	long-to-float v5, v3
	neg-long v12, v12
	and-int/2addr v7, v14
	shl-int/lit8 v80, v186, -83
	or-long v185, v198, v68
	xor-int/lit16 v2, v15, -4553
	div-int/lit16 v14, v15, -22962
	mul-float/2addr v5, v11
	const-wide v8, 0xe17a3d88b04ec9c7L
	rem-double/2addr v0, v8
	xor-long v23, v183, v161
	or-int/lit8 v15, v15, 116
	div-int/2addr v14, v15
	const-wide v21, 8192L
	or-long v12, v12, v21
	div-long/2addr v3, v12
	add-long v189, v50, v226
	add-int/lit8 v204, v229, -98
	not-int v5, v14
	mul-float v38, v11, v177
	add-float v14, v31, v171
	and-long/2addr v3, v12
	add-float/2addr v14, v11
	sub-long/2addr v3, v12
	div-int/lit8 v77, v90, 55
	mul-double/2addr v8, v0
	rem-int/lit8 v102, v250, -114
	rem-double/2addr v0, v8
	xor-int/lit8 v172, v252, -100
	not-int v2, v15
	or-int/lit16 v6, v7, -28091
	const-wide v129, 1024L
	or-long v12, v12, v129
	rem-long/2addr v3, v12
	mul-int/lit16 v11, v6, 25817
	rem-double/2addr v8, v0
	div-double/2addr v0, v8
	const-wide v211, 524288L
	or-long v12, v12, v211
	div-long/2addr v3, v12
	add-double v10, v195, v88
	rem-float v126, v210, v163
	shl-long/2addr v3, v2
	add-double v233, v137, v92
	int-to-float v1, v6
	rem-float/2addr v14, v1
	and-long v230, v3, v161
	int-to-double v1, v6
	float-to-long v14, v14
	not-int v7, v6
	shr-int/lit8 v71, v228, 14
	const-wide v226, 4096L
	or-long v226, v226, v226
	rem-long v8, v14, v226
	not-long v14, v14
	rem-int/lit16 v0, v6, 21428
	or-int/2addr v0, v5
	or-int/lit8 v7, v7, 86
	rem-int/2addr v0, v7
	or-int/lit8 v5, v5, 57
	rem-int/2addr v6, v5
	shl-int/2addr v0, v5
	xor-int/2addr v5, v0
	const v6, 0x7c391db
	float-to-double v11, v6
	long-to-int v12, v3
	ushr-int v230, v172, v29
	float-to-int v4, v6
	const v0, 0xa9095d02
	rem-float/2addr v0, v6
	neg-int v12, v7
	shr-int/lit8 v232, v251, -39
	div-float v86, v42, v140
	sub-double v107, v1, v173
	xor-long v174, v68, v198
	shl-int/lit8 v252, v36, 73
	div-int/lit8 v202, v132, 76
	double-to-long v5, v1
	and-int/2addr v4, v7
	int-to-long v10, v12
	sub-float v131, v85, v42
	neg-long v1, v8
	shl-int/lit8 v5, v228, -46
	int-to-double v8, v5
	or-int/lit8 v20, v20, 93
	div-int v151, v28, v20
	ushr-int v182, v132, v237
	add-int/lit8 v104, v252, -33
	int-to-long v15, v4
	double-to-long v6, v8
	sub-float v205, v197, v0
	ushr-long/2addr v6, v12
	div-float v154, v85, v42
	or-int/lit8 v4, v4, 93
	rem-int/2addr v5, v4
	ushr-long/2addr v1, v12
	rem-int/lit16 v0, v12, -11196
	const v5, 0x1621fb09
	const v3, 0x64666605
	add-float/2addr v3, v5
	rem-float/2addr v3, v5
	neg-float v12, v3
	div-int/lit16 v2, v0, -21822
	ushr-long v94, v198, v102
	shl-int/lit8 v57, v192, 1
	shl-long/2addr v10, v2
	ushr-int/lit8 v2, v36, -4
	div-float/2addr v5, v12
	and-int/2addr v0, v2
	and-int/2addr v2, v0
	div-float/2addr v5, v3
	double-to-float v5, v8
	sub-long v152, v50, v68
	and-long v206, v166, v183
	add-int/lit16 v2, v2, 10200
	mul-int/lit8 v30, v44, 11
	shr-int/2addr v2, v4
	const-wide v189, 16L
	or-long v10, v10, v189
	div-long/2addr v6, v10
	long-to-double v4, v15
	mul-double/2addr v8, v4
	and-long/2addr v6, v10
	mul-float/2addr v3, v12
	long-to-double v10, v10
	div-double/2addr v8, v10
	float-to-int v3, v3
	const v7, 0x48edc511
	sub-float/2addr v12, v7
	double-to-int v12, v10
	add-float v23, v177, v140
	int-to-double v11, v12
	mul-double v225, v244, v11
	add-int/2addr v0, v2
	add-float v192, v85, v140
	ushr-long/2addr v15, v3
	move-wide/from16 v5, v158
	sub-long/2addr v15, v5
	neg-long v14, v15
	mul-int v5, v168, v2
	div-int/lit16 v13, v0, 5134
	xor-long v176, v235, v158
	sub-int/2addr v3, v13
	rsub-int/lit8 v149, v204, 80
	or-int/lit8 v222, v222, 112
	div-int v201, v115, v222
	shl-int/2addr v0, v3
	shl-int/2addr v13, v3
	int-to-float v3, v2
	float-to-int v8, v7
	add-double v63, v248, v107
	sub-long v60, v211, v246
	shr-int/2addr v5, v8
	rem-float/2addr v7, v3
	div-double v132, v225, v39
	ushr-long v54, v14, v115
	xor-int v211, v169, v164
	float-to-double v9, v3
	div-float v235, v7, v131
	not-long v10, v14
	or-int/lit8 v75, v75, 84
	rem-int v220, v102, v75
	move-wide/from16 v2, v271
	move-wide/from16 v13, v269
	mul-double/2addr v2, v13
	sub-long v120, v183, v122
	move/from16 v3, v262
	div-float/2addr v7, v3
	rsub-int/lit8 v236, v228, -51
	long-to-double v9, v10
	shl-int/2addr v8, v0
	mul-int v179, v116, v220
	shr-int/2addr v8, v5
	const-wide v10, 0xff16b92fabc3b95cL
	const-wide v11, 0x53b13618ba6eef94L
	const-wide v11, 0x6a1da55724e7d704L
	const-wide v11, 0xef0a3f0e44138fa2L
	const-wide v2, 0xeeaf953d6619d776L
	const-wide v246, 4096L
	or-long v2, v2, v246
	rem-long/2addr v11, v2
	rem-int/lit16 v15, v0, -25099
	mul-float v244, v38, v210
	const-wide v12, 0xa5b7250e89f295e4L
	move-wide/from16 v4, v107
	rem-double/2addr v12, v4
	const-wide v0, 0x8dfae906fe03af40L
	mul-long/2addr v0, v2
	and-long v33, v152, v100
	xor-int/lit8 v8, v251, 83
	const v5, 0xd4a407d0
	mul-float/2addr v7, v5
	or-long/2addr v2, v0
	mul-int/lit8 v244, v169, 42
	or-int v157, v74, v44
	and-long v108, v155, v161
	mul-float/2addr v7, v5
	int-to-long v3, v8
	float-to-long v11, v5
	int-to-long v10, v15
	shr-int/lit8 v165, v25, 94
	div-int/lit16 v0, v15, -28542
	float-to-int v1, v7
	rem-float/2addr v5, v7
	or-int/lit8 v1, v1, 77
	rem-int/2addr v15, v1
	div-double v205, v88, v216
	ushr-int v172, v251, v102
	shl-long/2addr v10, v1
	xor-int/lit8 v243, v178, 14
	sub-float/2addr v7, v5
	add-int/lit16 v10, v0, -31555
	neg-int v0, v1
	move-wide/from16 v3, v92
	move-wide/from16 v3, v205
	move-wide/from16 v8, v195
	mul-double/2addr v8, v3
	sub-int/2addr v1, v15
	int-to-long v15, v0
	and-int/lit8 v147, v151, -6
	not-int v8, v0
	rem-double v208, v240, v63
	long-to-int v10, v15
	const-wide v122, 32768L
	or-long v15, v15, v122
	div-long v179, v21, v15
	long-to-int v0, v15
	add-float v227, v23, v200
	int-to-char v12, v8
	and-int/2addr v10, v0
	shr-long/2addr v15, v8
	const-wide v14, 0x95243cd9b8db42f2L
	move-wide/from16 v11, v183
	mul-long/2addr v14, v11
	and-int v25, v0, v202
	and-int/lit16 v12, v0, -24193
	const-wide v3, 0x83d3386675e7bd1eL
	move-wide/from16 v5, v46
	add-double/2addr v5, v3
	div-double/2addr v3, v5
	sub-long v53, v246, v108
	add-float v163, v38, v58
	and-int v152, v147, v243
	and-int/2addr v0, v8
	mul-int/lit16 v7, v1, 13634
	const-wide v14, 134217728L
	or-long v100, v100, v14
	rem-long v166, v33, v100
	move-wide/from16 v1, v129
	mul-long/2addr v14, v1
	const v0, 0xc5eae53b
	neg-float v15, v0
	const-wide v10, 0x1d1641a3c87738bfL
	mul-long/2addr v1, v10
	sub-double/2addr v5, v3
	or-int/lit8 v12, v12, 59
	div-int/2addr v7, v12
	and-int/2addr v8, v12
	double-to-long v14, v5
	int-to-short v0, v8
	add-float v36, v192, v131
	mul-int v89, v237, v77
	div-int/lit8 v83, v169, -76
	shr-long v229, v53, v251
	xor-int/2addr v0, v7
	const-wide v246, 16384L
	or-long v120, v120, v246
	div-long v116, v53, v120
	neg-double v5, v3
	move/from16 v6, v85
	const v15, 0x381dbafb
	div-float/2addr v15, v6
	add-float/2addr v6, v15
	double-to-long v6, v3
	not-int v5, v8
	shl-int v102, v244, v75
	add-double v186, v240, v132
	const v2, 0xb28ae9a6
	div-float/2addr v15, v2
	int-to-byte v8, v8
	neg-int v0, v5
	int-to-char v2, v5
	and-long/2addr v10, v6
	or-long/2addr v6, v10
	shl-int/2addr v0, v8
	const-wide v116, 33554432L
	or-long v10, v10, v116
	div-long/2addr v6, v10
	ushr-int/2addr v12, v2
	int-to-char v4, v0
	and-int/2addr v2, v8
	sub-int/2addr v5, v12
	shl-long v22, v144, v83
	move/from16 v9, v262
	rem-float/2addr v15, v9
	ushr-long v23, v246, v19
	sub-float v223, v31, v18
	int-to-long v0, v8
	add-long v188, v127, v6
	int-to-char v12, v5
	add-int/2addr v8, v2
	rem-int/lit8 v174, v164, 94
	mul-int/2addr v5, v8
	rem-int/lit16 v6, v8, 22511
	move-wide/from16 v0, v208
	neg-double v10, v0
	sub-double v169, v240, v233
	or-int v201, v41, v254
	add-int v167, v165, v194
	double-to-int v3, v0
	sub-int/2addr v12, v6
	const-wide v2, 0xda8bbdbf4eafb2efL
	long-to-int v12, v2
	double-to-int v15, v0
	float-to-int v8, v9
	mul-int/2addr v8, v5
	float-to-long v3, v9
	move/from16 v6, v160
	mul-float/2addr v6, v9
	shr-long v125, v179, v72
	rem-double/2addr v0, v10
	add-float v206, v6, v235
	xor-int/lit16 v2, v8, -25857
	ushr-int/2addr v8, v12
	and-int/lit8 v205, v222, 40
	or-int/lit8 v8, v8, 113
	div-int/2addr v15, v8
	rem-double/2addr v0, v10
	and-int v189, v168, v202
	or-int/lit8 v80, v80, 90
	div-int v108, v136, v80
	shl-int/2addr v2, v12
	or-long v155, v110, v125
	sub-long v23, v179, v120
	rem-double v79, v10, v132
	or-int/2addr v8, v15
	or-int/lit8 v5, v5, 48
	rem-int/2addr v8, v5
	int-to-long v13, v5
	neg-float v12, v6
	neg-long v1, v3
	shr-long v122, v100, v152
	shl-int/2addr v5, v15
	ushr-long v53, v33, v236
	ushr-long/2addr v13, v5
	const-wide v176, 131072L
	or-long v161, v161, v176
	div-long v17, v183, v161
	float-to-long v9, v9
	and-int/lit8 v50, v243, 61
	mul-int/lit16 v1, v8, 7572
	shr-long/2addr v9, v15
	div-float/2addr v6, v12
	int-to-byte v6, v15
	and-long v191, v53, v9
	ushr-int v158, v181, v29
	shl-long v237, v127, v189
	and-long v153, v13, v125
	rem-int/lit16 v2, v15, 7618
	or-int/2addr v5, v15
	const-wide v13, 0x38c24e569644fdeL
	double-to-long v11, v13
	move/from16 v7, v223
	const v3, 0x85f7114b
	add-float/2addr v3, v7
	xor-long/2addr v9, v11
	sub-float v36, v197, v131
	move-wide/from16 v12, v248
	const-wide v0, 0x7527ddcda2f50494L
	add-double/2addr v0, v12
	not-long v2, v9
	double-to-long v1, v0
	shr-long v43, v144, v43
	rem-int/lit16 v1, v15, 4975
	rem-int/lit16 v10, v1, 137
	and-long v249, v183, v179
	xor-int v223, v136, v253
	shl-int/2addr v6, v15
	int-to-long v9, v6
	shr-int/lit8 v222, v220, -53
	int-to-long v5, v6
	sub-int/2addr v15, v8
	long-to-double v1, v9
	ushr-int/2addr v15, v8
	div-double/2addr v1, v12
	shr-int v132, v181, v75
	not-long v11, v9
	or-int/lit8 v165, v165, 98
	rem-int v57, v87, v165
	mul-float v120, v160, v140
	int-to-double v3, v8
	int-to-short v10, v8
	and-int/lit16 v9, v8, -7948
	mul-int/lit8 v129, v151, 127
	or-int/lit8 v10, v10, 19
	div-int/2addr v9, v10
	rem-int/lit8 v8, v254, 63
	and-int v150, v174, v143
	or-int/lit16 v2, v10, 3814
	double-to-float v13, v3
	mul-float/2addr v13, v7
	or-long/2addr v5, v11
	rsub-int v13, v8, -24222
	and-long/2addr v11, v5
	shl-int/2addr v8, v2
	const-wide v179, 512L
	or-long v144, v144, v179
	rem-long v130, v237, v144
	xor-int/lit8 v114, v115, -74
	long-to-int v1, v5
	or-long v230, v191, v179
	ushr-long/2addr v5, v15
	mul-int/2addr v2, v13
	shl-int/2addr v8, v15
	move-wide/from16 v11, v225
	sub-double/2addr v11, v3
	shr-long/2addr v5, v2
	mul-int v177, v89, v181
	add-double v157, v46, v240
	mul-double v169, v92, v225
	const-wide v2, 0x242aceca2e9888d5L
	const-wide v161, 8388608L
	or-long v5, v5, v161
	rem-long/2addr v2, v5
	add-int v247, v232, v228
	sub-int/2addr v8, v9
	ushr-int/2addr v9, v13
	xor-long v248, v100, v110
	xor-int v136, v143, v104
	sub-long v137, v33, v5
	add-double v114, v195, v240
	and-long v17, v5, v68
	and-int/lit8 v222, v189, 22
	ushr-int/lit8 v128, v182, 124
	rem-int/lit16 v4, v8, -6896
	shr-long/2addr v5, v4
	ushr-long/2addr v5, v1
	and-int/lit8 v150, v87, -127
	or-int/2addr v15, v10
	mul-long/2addr v5, v2
	const-wide v0, 0xcf497f2394537a85L
	mul-double/2addr v0, v11
	div-int/lit16 v13, v4, 20145
	mul-int/lit16 v11, v8, -27135
	shl-int v192, v9, v182
	sub-float v7, v163, v86
	add-long/2addr v5, v2
	add-double v150, v46, v195
	rem-float v123, v206, v36
	or-int/lit8 v167, v167, 30
	div-int v74, v204, v167
	or-int/lit8 v13, v13, 125
	rem-int/2addr v8, v13
	double-to-int v2, v0
	xor-int/lit16 v5, v13, -22780
	const v11, 0xd770cc32
	div-float/2addr v11, v7
	int-to-long v14, v5
	rsub-int v14, v4, -13316
	or-long v210, v161, v125
	div-int/lit8 v191, v50, 23
	ushr-long v75, v116, v247
	and-int/lit8 v21, v71, -62
	shl-long v113, v100, v20
	mul-float v37, v38, v85
	float-to-double v4, v7
	ushr-int/2addr v10, v13
	const-wide v5, 0x9b882101839b7c32L
	shl-long/2addr v5, v2
	xor-int/lit8 v8, v129, 6
	shr-long/2addr v5, v8
	or-int/2addr v8, v2
	rsub-int v15, v2, -25715
	mul-long v209, v161, v144
	or-long v189, v248, v183
	move-wide/from16 v10, v155
	add-long/2addr v5, v10
	const v8, 0x1becb728
	div-float/2addr v7, v8
	float-to-double v0, v7
	div-float/2addr v8, v7
	mul-long v239, v144, v110
	mul-int v159, v167, v87
	const-wide v248, 4194304L
	or-long v198, v198, v248
	rem-long v208, v100, v198
	xor-int v161, v165, v2
	shr-int/lit8 v36, v143, -55
	sub-float v107, v206, v86
	mul-float/2addr v7, v8
	shl-long/2addr v10, v15
	or-long v63, v183, v144
	long-to-float v13, v10
	rem-double v113, v195, v150
	shr-long v9, v198, v174
	float-to-long v14, v13
	const-wide v15, 0xce292a4bc377d6f2L
	div-double/2addr v15, v0
	add-int/lit8 v227, v20, -7
	const v1, 0xf16443e3
	add-int/2addr v1, v2
	const-wide v43, 4L
	or-long v23, v23, v43
	div-long v87, v155, v23
	shl-long/2addr v9, v2
	or-int/lit16 v2, v2, 27263
	or-int/lit8 v90, v90, 108
	div-int v50, v71, v90
	const-wide v130, 8192L
	or-long v9, v9, v130
	rem-long/2addr v5, v9
	div-int/lit16 v5, v2, 17977
	move-wide/from16 v7, v75
	and-long/2addr v9, v7
	sub-int/2addr v2, v1
	shr-int/2addr v1, v5
	sub-float v142, v37, v123
	or-int/lit8 v201, v201, 99
	rem-int v8, v84, v201
	or-int/lit8 v191, v191, 87
	div-int v235, v71, v191
	ushr-int/2addr v5, v1
	shr-int v68, v254, v181
	shr-int v41, v90, v112
	or-int/lit8 v5, v5, 4
	rem-int/2addr v1, v5
	rsub-int/lit8 v242, v181, -100
	rem-float v248, v206, v85
	long-to-float v15, v9
	not-int v11, v2
	add-int/lit16 v6, v2, -18428
	const-wide v6, 0x68435c3fcab5f4d9L
	const-wide v189, 33554432L
	or-long v9, v9, v189
	rem-long/2addr v6, v9
	float-to-int v3, v15
	xor-long/2addr v6, v9
	ushr-long/2addr v6, v2
	div-int/lit16 v5, v11, 18831
	const-wide v125, 1024L
	or-long v9, v9, v125
	div-long/2addr v6, v9
	rem-int/lit8 v113, v72, -114
	xor-long v21, v183, v144
	div-double v237, v92, v216
	div-int/lit8 v143, v98, 96
	add-int v50, v132, v108
	xor-int v56, v129, v108
	move-wide/from16 v10, v157
	const-wide v9, 0x7fc4ffc4ea830c40L
	const-wide v8, 0x3d1acf5c2193d878L
	const-wide v8, 0x22b986930ebb6fb9L
	move-wide/from16 v13, v79
	sub-double/2addr v13, v8
	neg-double v10, v13
	double-to-float v3, v13
	add-long v113, v63, v33
	ushr-long v17, v198, v102
	sub-long v217, v60, v110
	add-int/lit16 v11, v2, 28547
	ushr-long/2addr v6, v11
	add-int/2addr v1, v5
	not-int v3, v5
	shl-long/2addr v6, v2
	neg-double v6, v13
	move-wide/from16 v1, v43
	const-wide v3, 0x4c85884fbbcb0681L
	and-long/2addr v1, v3
	const-wide v75, 524288L
	or-long v3, v3, v75
	div-long/2addr v1, v3
	div-double v80, v150, v13
	div-int/lit8 v163, v143, -100
	mul-float v94, v200, v142
	shl-long v42, v53, v242
	div-float v149, v206, v86
	div-double v61, v233, v157
	sub-int/2addr v11, v5
	ushr-int/2addr v11, v5
	xor-int/lit8 v81, v36, -82
	div-double/2addr v13, v8
	neg-float v9, v15
	or-long/2addr v1, v3
	neg-double v12, v13
	shr-int/2addr v11, v5
	not-int v4, v11
	xor-int/2addr v5, v4
	add-double/2addr v12, v6
	and-int v28, v25, v135
	and-int/lit8 v173, v56, 23
	or-int/lit16 v14, v4, 15286
	mul-long v77, v230, v21
	and-long v32, v66, v77
	xor-int/2addr v14, v11
	const-wide v11, 0xa85bc764b9f2b7c5L
	xor-long/2addr v11, v1
	long-to-float v3, v1
	or-int/2addr v4, v14
	or-int/2addr v5, v14
	and-int/lit8 v17, v129, -95
	add-int v139, v191, v251
	div-int/lit16 v15, v14, -22611
	int-to-double v14, v15
	and-long/2addr v11, v1
	const-wide v63, 16L
	or-long v217, v217, v63
	rem-long v18, v208, v217
	div-int/lit8 v59, v28, -95
	long-to-double v1, v1
	div-double v109, v225, v6
	mul-int/lit16 v0, v4, -32280
	sub-int v106, v50, v68
	const-wide v1, 0x137f86a31c6c59bbL
	mul-long/2addr v1, v11
	shl-int/2addr v0, v5
	float-to-double v13, v9
	neg-double v9, v6
	neg-long v13, v1
	float-to-int v10, v3
	or-int/lit16 v12, v0, -29925
	rsub-int/lit8 v148, v30, 71
	double-to-int v5, v6
	add-int/lit16 v8, v4, -16256
	xor-long/2addr v13, v1
	float-to-long v0, v3
	move-wide/from16 v2, v61
	add-double/2addr v2, v6
	mul-int/lit8 v51, v222, -34
	sub-double v171, v169, v92
	add-float v3, v248, v27
	rem-float v91, v206, v107
	int-to-byte v5, v5
	add-int/2addr v12, v4
	add-int/lit8 v138, v12, -98
	sub-int v225, v103, v254
	or-int/lit8 v235, v235, 81
	rem-int v57, v178, v235
	rem-float v108, v94, v123
	shr-int/lit8 v133, v106, 15
	ushr-int/lit8 v244, v177, -117
	rem-int/lit16 v11, v5, 12247
	shl-long v71, v66, v173
	neg-long v7, v0
	mul-double v43, v150, v157
	rsub-int v6, v4, -7376
	mul-double v73, v61, v92
	shl-long/2addr v0, v4
	and-int v181, v202, v89
	move/from16 v5, v206
	mul-float/2addr v5, v3
	or-int/lit8 v11, v11, 108
	rem-int/2addr v4, v11
	move-wide/from16 v5, v157
	move-wide/from16 v6, v169
	move-wide/from16 v12, v150
	mul-double/2addr v12, v6
	shl-int v172, v165, v181
	or-int/lit8 v11, v11, 116
	rem-int/2addr v10, v11
	shl-int/2addr v11, v10
	const v12, 0xda132cf7
	mul-float/2addr v12, v3
	double-to-float v9, v6
	move-wide/from16 v14, v63
	mul-long/2addr v0, v14
	div-int/lit16 v0, v10, -20269
	int-to-double v9, v0
	shl-long v179, v183, v129
	shr-int/lit8 v146, v41, 42
	shr-int v172, v20, v59
	and-int v213, v251, v178
	shl-long v32, v144, v59
	sub-int/2addr v11, v0
	int-to-byte v14, v11
	shl-int/2addr v11, v0
	add-float v168, v248, v27
	rem-int/lit16 v1, v14, -11800
	sub-int/2addr v11, v0
	ushr-int/lit8 v44, v161, -45
	xor-long v30, v113, v179
	neg-double v9, v9
	int-to-long v12, v4
	move-wide/from16 v0, v263
	const-wide v32, 8L
	or-long v12, v12, v32
	div-long/2addr v0, v12
	and-int/lit8 v47, v191, -12
	add-double v50, v169, v9
	int-to-byte v13, v4
	add-int/lit16 v12, v4, -15694
	int-to-short v4, v13
	double-to-int v13, v9
	int-to-byte v3, v14
	neg-long v13, v0
	ushr-int/lit8 v251, v41, -33
	int-to-short v14, v3
	neg-double v11, v6
	int-to-double v5, v14
	rem-int/lit8 v215, v242, 67
	shl-long/2addr v0, v4
	shr-long v14, v71, v25
	sub-double v6, v9, v237
	or-int/lit8 v33, v97, 102
	shr-long v171, v113, v213
	mul-long/2addr v14, v0
	div-int/lit8 v27, v173, -5
	const v13, 0xdc7e1e4e
	const v7, 0x4fadfaf2
	mul-float/2addr v13, v7
	not-long v8, v14
	or-long/2addr v14, v8
	add-double v16, v169, v237
	neg-long v7, v8
	ushr-int/2addr v3, v4
	and-int/lit8 v198, v133, -58
	or-int/lit8 v232, v232, 70
	rem-int v25, v81, v232
	add-int/2addr v3, v4
	and-int/lit16 v11, v4, 30006
	shr-long/2addr v0, v3
	add-int v86, v194, v118
	or-long v14, v125, v116
	const-wide v21, 1024L
	or-long v7, v7, v21
	div-long/2addr v14, v7
	const-wide v15, 0xd5753f23199e75f6L
	neg-double v9, v15
	mul-long/2addr v0, v7
	sub-int v42, v98, v104
	xor-long v147, v153, v208
	or-int/lit16 v13, v11, -26598
	xor-long v180, v0, v53
	ushr-int/lit8 v249, v219, 126
	or-int/lit16 v10, v3, -30046
	and-int/2addr v4, v13
	or-int/lit16 v15, v4, 1614
	const-wide v5, 0x69d1db4289945066L
	const-wide v7, 0xffd95fa76cc237c5L
	rem-double/2addr v7, v5
	ushr-int/lit8 v199, v204, -103
	const-wide v12, 0xabd0faf3028d5e0cL
	xor-long/2addr v12, v0
	move/from16 v4, v107
	float-to-int v12, v4
	long-to-int v9, v0
	const-wide v14, 0x7f26a5cdf4b645aeL
	const-wide v75, 268435456L
	or-long v14, v14, v75
	rem-long/2addr v0, v14
	or-long v141, v14, v125
	float-to-double v13, v4
	mul-int v36, v164, v146
	sub-int v175, v225, v202
	add-long v101, v87, v75
	div-int/lit16 v7, v10, -14052
	rsub-int v7, v3, 8430
	or-long v141, v171, v63
	add-int/lit8 v247, v86, 52
	const v10, 0xd17ad7ae
	rem-float/2addr v4, v10
	xor-int/lit8 v105, v103, -108
	int-to-float v1, v7
	and-int/lit8 v192, v253, -124
	int-to-char v8, v11
	mul-int/lit16 v10, v7, 12396
	float-to-long v1, v4
	sub-int v155, v3, v249
	ushr-int/2addr v8, v10
	float-to-long v11, v4
	mul-float v180, v85, v168
	and-long v212, v183, v66
	add-int/2addr v10, v8
	or-int/2addr v8, v9
	or-int/lit8 v165, v165, 113
	rem-int v163, v83, v165
	const v4, 0x2f363e20
	const v13, 0xcca44842
	add-float/2addr v4, v13
	shr-long v2, v11, v167
	or-int/2addr v9, v8
	float-to-double v15, v4
	shr-int/lit8 v61, v28, -26
	float-to-double v1, v13
	mul-float v29, v120, v58
	const-wide v5, 0xe5918017c9113017L
	xor-long/2addr v5, v11
	double-to-float v1, v1
	add-int/lit8 v203, v194, -23
	long-to-double v14, v5
	shl-long v131, v53, v242
	mul-int v86, v252, v221
	const-wide v125, 67108864L
	or-long v5, v5, v125
	div-long/2addr v11, v5
	mul-long/2addr v5, v11
	add-float v13, v206, v120
	mul-float/2addr v1, v13
	or-int/lit8 v7, v7, 66
	div-int/2addr v8, v7
	int-to-byte v10, v7
	and-int v110, v159, v28
	div-float/2addr v4, v1
	xor-long v69, v230, v141
	const-wide v144, 524288L
	or-long v23, v23, v144
	div-long v110, v75, v23
	const-wide v101, 2L
	or-long v217, v217, v101
	div-long v71, v212, v217
	div-int/lit8 v83, v244, 118
	or-int/lit8 v44, v44, 94
	div-int v175, v244, v44
	or-int/2addr v7, v9
	rsub-int/lit8 v100, v106, -127
	div-double v118, v169, v237
	shl-int/2addr v10, v8
	const-wide v53, 4L
	or-long v113, v113, v53
	rem-long v223, v183, v113
	xor-int/lit8 v163, v33, 114
	shl-int/lit8 v150, v159, -60
	rem-float v178, v13, v149
	add-float v132, v108, v149
	ushr-int v149, v106, v192
	or-int/lit8 v47, v47, 88
	rem-int v228, v204, v47
	or-int/lit8 v143, v143, 77
	rem-int v248, v7, v143
	mul-double v182, v50, v186
	ushr-long/2addr v11, v9
	and-int/lit8 v51, v204, -22
	xor-int/2addr v8, v7
	mul-int v31, v215, v236
	sub-int/2addr v8, v10
	add-double v140, v39, v92
	double-to-int v10, v14
	not-long v6, v5
	neg-double v0, v14
	ushr-int v149, v97, v47
	or-int v27, v143, v104
	const-wide v110, 131072L
	or-long v11, v11, v110
	rem-long/2addr v6, v11
	ushr-long/2addr v6, v8
	mul-int/lit8 v211, v161, -55
	int-to-double v6, v8
	double-to-long v13, v0
	xor-long/2addr v13, v11
	xor-int v221, v221, v201
	mul-int/lit8 v194, v20, -123
	mul-long v73, v18, v147
	add-double/2addr v0, v6
	ushr-int/2addr v9, v10
	add-double/2addr v6, v0
	const-wide v217, 256L
	or-long v21, v21, v217
	rem-long v100, v239, v21
	const v4, 0x47368035
	move/from16 v15, v58
	sub-float/2addr v4, v15
	xor-long v252, v66, v217
	or-long/2addr v11, v13
	sub-double/2addr v6, v0
	or-int/lit8 v8, v8, 20
	div-int/2addr v10, v8
	rem-int/lit16 v15, v9, -22240
	and-int/2addr v8, v15
	const-wide v212, 2048L
	or-long v11, v11, v212
	rem-long/2addr v13, v11
	or-int/lit8 v249, v249, 86
	div-int v230, v251, v249
	rem-int/lit16 v10, v9, -17440
	sub-int/2addr v9, v15
	neg-float v8, v4
	and-int/lit16 v6, v10, -29561
	shl-int/2addr v10, v15
	mul-int/lit16 v11, v9, -21573
	or-int/lit8 v11, v11, 26
	div-int/2addr v6, v11
	ushr-int/lit8 v155, v129, 121
	or-int/lit8 v9, v9, 91
	div-int v10, v248, v9
	mul-int/2addr v15, v11
	not-int v1, v6
	and-long v170, v75, v144
	xor-int/lit8 v14, v146, 116
	div-double v218, v186, v237
	or-int/lit16 v12, v11, 31786
	float-to-int v10, v8
	div-float/2addr v8, v4
	move-wide/from16 v0, v157
	neg-double v0, v0
	mul-int/lit16 v11, v12, 184
	double-to-float v2, v0
	move-wide/from16 v13, v23
	const-wide v10, 0x338d860ac43d5ebaL
	const-wide v73, 65536L
	or-long v13, v13, v73
	div-long/2addr v10, v13
	const-wide v9, 0x1ba2b6c9ece5cbb6L
	add-double/2addr v9, v0
	and-int v251, v103, v105
	int-to-double v13, v12
	or-int/lit8 v173, v173, 65
	div-int v220, v192, v173
	int-to-float v10, v15
	add-int/lit8 v163, v97, -25
	or-int/lit8 v15, v15, 16
	div-int/2addr v12, v15
	div-double v117, v233, v0
	sub-float v152, v8, v58
	sub-long v234, v252, v87
	add-float/2addr v8, v4
	const-wide v1, 0x5432ab613753b651L
	long-to-float v0, v1
	shr-long v85, v189, v255
	long-to-float v7, v1
	const-wide v2, 0xfbd809e417aa11c4L
	move-wide/from16 v3, v69
	const-wide v3, 0x2362d4a7eeb1dcebL
	move-wide/from16 v2, v110
	move-wide/from16 v9, v223
	and-long/2addr v9, v2
	or-int/lit8 v51, v51, 121
	div-int v22, v33, v51
	sub-long/2addr v9, v2
	const-wide v87, 64L
	or-long v110, v110, v87
	div-long v82, v77, v110
	add-int v2, v173, v42
	move-wide/from16 v10, v92
	div-double/2addr v13, v10
	sub-double v8, v218, v186
	ushr-int/lit8 v56, v2, 121
	sub-double v124, v218, v140
	shl-int/lit8 v214, v56, 55
	add-float/2addr v0, v7
	double-to-float v14, v13
	const-wide v6, 0x222764e205d46ce0L
	shl-long/2addr v6, v15
	const-wide v12, 0x5289b9ddc84f936aL
	mul-long/2addr v6, v12
	rem-int/lit16 v7, v15, -11465
	and-int/lit16 v4, v7, 15493
	ushr-int/2addr v2, v4
	or-int/lit16 v15, v15, 30861
	const-wide v212, 1024L
	or-long v53, v53, v212
	div-long v178, v75, v53
	sub-long v42, v178, v23
	shl-int/2addr v7, v4
	int-to-float v1, v2
	const-wide v11, 0x565c3458a9549905L
	move-wide/from16 v9, v147
	add-long/2addr v11, v9
	move-wide/from16 v12, v140
	move-wide/from16 v12, v269
	move-wide/from16 v13, v157
	const-wide v9, 0x468eb3e6dd8dc318L
	rem-double/2addr v13, v9
	or-int v129, v135, v97
	ushr-int/lit8 v220, v143, 14
	move-wide/from16 v10, v85
	move-wide/from16 v6, v113
	or-long/2addr v6, v10
	mul-double v226, v13, v237
	or-long/2addr v6, v10
	mul-long/2addr v10, v6
	neg-long v1, v10
	ushr-long v38, v66, v44
	shl-int/lit8 v177, v44, 24
	int-to-float v3, v4
	not-long v4, v10
	or-int/lit8 v22, v22, 112
	rem-int v70, v225, v22
	mul-int/lit8 v191, v149, -6
	double-to-float v4, v13
	mul-double v103, v226, v92
	not-long v7, v10
	or-int v205, v251, v198
	and-int v111, v177, v247
	const v9, 0xb052dc16
	or-int/2addr v15, v9
	and-long v145, v10, v85
	mul-int/lit8 v24, v159, -111
	mul-long/2addr v10, v1
	const-wide v252, 131072L
	or-long v7, v7, v252
	div-long/2addr v10, v7
	mul-float v234, v91, v197
	sub-double v216, v186, v195
	not-long v4, v1
	mul-int/lit8 v4, v242, -53
	neg-float v1, v3
	not-long v3, v10
	add-int/lit16 v13, v9, 122
	int-to-long v14, v9
	move-wide/from16 v5, v218
	move-wide/from16 v1, v117
	rem-double/2addr v5, v1
	double-to-int v1, v5
	and-long/2addr v14, v10
	and-int v245, v25, v242
	or-int/lit8 v1, v1, 119
	rem-int/2addr v9, v1
	and-long v231, v82, v3
	xor-int/2addr v9, v13
	shl-int v147, v220, v98
	ushr-long/2addr v3, v13
	float-to-long v11, v0
	int-to-char v9, v1
	rem-double v171, v117, v186
	not-long v7, v3
	xor-int/2addr v1, v9
	ushr-int/lit8 v236, v56, 97
	and-int/2addr v9, v13
	ushr-int/2addr v13, v9
	rem-int/lit8 v149, v138, -6
	mul-double v190, v216, v182
	float-to-long v15, v0
	or-int/lit16 v13, v13, -7638
	neg-int v5, v9
	or-int/lit8 v5, v5, 30
	div-int/2addr v9, v5
	mul-int v237, v194, v163
	long-to-double v0, v11
	and-int/lit8 v212, v47, 32
	double-to-float v12, v0
	and-int v201, v220, v214
	const v10, 0x22652177
	mul-float/2addr v10, v12
	ushr-int v55, v5, v255
	sub-float v137, v180, v197
	and-int v152, v230, v96
	xor-int/2addr v9, v13
	ushr-int/lit8 v158, v214, 37
	move-wide/from16 v7, v190
	sub-double/2addr v7, v0
	and-int/2addr v9, v5
	div-float/2addr v10, v12
	or-int/lit8 v5, v5, 56
	rem-int/2addr v13, v5
	int-to-short v10, v5
	neg-long v6, v15
	float-to-int v2, v12
	xor-int/lit8 v89, v31, -118
	mul-double v134, v103, v140
	shr-int/2addr v13, v9
	or-int v47, v44, v199
	div-int/lit16 v12, v2, -6429
	add-float v5, v91, v137
	const-wide v6, 0xda9e7aa987c6015cL
	mul-double/2addr v6, v0
	add-int/2addr v13, v10
	int-to-byte v8, v2
	sub-double/2addr v6, v0
	or-int/lit8 v8, v8, 93
	rem-int/2addr v10, v8
	not-long v2, v15
	or-int/lit16 v15, v12, 17371
	rem-double v140, v92, v182
	or-long v22, v208, v153
	rsub-int v8, v13, 16093
	move-wide/from16 v12, v71
	and-long/2addr v2, v12
	or-int/lit16 v14, v10, 14754
	and-long v75, v223, v145
	shl-int v37, v203, v165
	mul-int/lit8 v89, v143, -122
	const-wide v113, 67108864L
	or-long v2, v2, v113
	rem-long/2addr v12, v2
	or-int/lit8 v231, v152, -84
	double-to-int v5, v0
	long-to-float v11, v2
	long-to-float v1, v2
	mul-long/2addr v12, v2
	float-to-int v13, v1
	div-int/lit8 v108, v139, -104
	add-long v141, v82, v100
	shl-int/2addr v5, v9
	and-int/lit16 v0, v15, -12145
	xor-int/lit16 v15, v0, 15922
	move-wide/from16 v1, v100
	const-wide v6, 0xb9e3c7d4e60d4feL
	xor-long/2addr v1, v6
	mul-long v45, v75, v113
	or-long v17, v18, v223
	add-double v33, v218, v182
	const v10, 0xfe54d8c9
	div-float/2addr v10, v11
	ushr-int/lit8 v46, v9, -34
	neg-float v1, v11
	rem-int/lit8 v82, v152, -23
	div-int/lit8 v142, v90, 44
	move-wide/from16 v9, v85
	sub-long/2addr v6, v9
	xor-long/2addr v9, v6
	sub-long/2addr v6, v9
	mul-int v199, v59, v46
	rem-int/lit8 v182, v97, 59
	move-wide/from16 v8, v186
	move-wide/from16 v8, v195
	move-wide/from16 v13, v273
	rem-double/2addr v13, v8
	and-int/2addr v5, v0
	sub-float v225, v197, v180
	move-wide/from16 v14, v22
	mul-long/2addr v14, v6
	xor-long/2addr v6, v14
	mul-int/2addr v5, v0
	mul-int/lit8 v137, v174, 2
	add-int/lit16 v11, v5, -12764
	add-int/lit16 v12, v0, 6305
	double-to-int v12, v8
	move/from16 v7, v58
	add-float/2addr v1, v7
	int-to-short v13, v5
	shr-int/2addr v13, v5
	rsub-int/lit8 v127, v51, 21
	ushr-int/lit8 v159, v177, -52
	move-wide/from16 v2, v66
	add-long/2addr v2, v14
	sub-long v0, v66, v153
	int-to-char v1, v12
	const v8, 0x9f77faee
	mul-float/2addr v8, v7
	sub-int v190, v194, v220
	shl-int v15, v57, v56
	add-long v221, v75, v100
	neg-int v4, v15
	shl-long/2addr v2, v13
	shr-long v226, v178, v177
	or-long v38, v17, v2
	add-int/lit16 v14, v5, 2958
	move-wide/from16 v4, v33
	const-wide v5, 0xa8870b1a41f61683L
	move-wide/from16 v14, v134
	sub-double/2addr v14, v5
	xor-long v10, v153, v53
	shr-int v154, v242, v57
	int-to-long v11, v1
	div-float v242, v58, v234
	float-to-double v2, v8
	mul-double/2addr v14, v5
	rem-float v210, v132, v58
	int-to-float v1, v13
	rem-int/lit16 v13, v13, -11536
	or-long v69, v75, v252
	add-int/lit8 v115, v215, 44
	sub-float/2addr v8, v7
	neg-double v15, v14
	long-to-float v2, v11
	move/from16 v10, v237
	or-int/lit8 v13, v13, 77
	rem-int/2addr v10, v13
	xor-int/lit16 v2, v13, 20054
	neg-float v5, v8
	mul-int/2addr v13, v2
	mul-int/2addr v10, v2
	shr-int/lit8 v123, v57, -69
	xor-int/2addr v10, v2
	not-int v3, v13
	add-double v249, v218, v216
	int-to-short v2, v10
	sub-double v33, v218, v249
	and-int/lit8 v112, v41, -73
	rsub-int v3, v10, 8829
	not-long v8, v11
	and-int/lit16 v2, v10, 28966
	mul-float/2addr v5, v1
	shl-int/lit8 v52, v228, -45
	xor-long v181, v11, v66
	shr-int v103, v123, v248
	shl-long/2addr v11, v3
	mul-long/2addr v8, v11
	and-int v104, v81, v46
	or-int/lit8 v108, v108, 28
	rem-int v34, v103, v108
	ushr-int/2addr v13, v2
	double-to-long v14, v15
	or-int/2addr v2, v10
	const-wide v75, 8388608L
	or-long v11, v11, v75
	rem-long/2addr v14, v11
	sub-long/2addr v11, v8
	const-wide v63, 4L
	or-long v11, v11, v63
	div-long/2addr v8, v11
	add-float v92, v200, v5
	rem-int/lit16 v0, v3, 5176
	mul-int/lit8 v71, v51, 49
	add-float v111, v58, v180
	move-wide/from16 v5, v249
	double-to-long v10, v5
	mul-int/lit16 v9, v0, 1658
	neg-double v12, v5
	mul-long/2addr v10, v14
	float-to-int v10, v7
	rem-int/lit16 v5, v0, -3766
	add-int/2addr v5, v2
	add-int/lit8 v44, v251, -8
	int-to-long v10, v5
	float-to-int v3, v1
	div-int/lit16 v14, v3, -31932
	int-to-byte v0, v14
	rem-int/lit16 v2, v0, -19624
	or-int/lit8 v14, v14, 34
	div-int/2addr v9, v14
	and-int/2addr v14, v3
	long-to-float v7, v10
	ushr-long/2addr v10, v0
	ushr-int v126, v24, v150
	double-to-long v13, v12
	mul-int v85, v115, v55
	div-float v145, v160, v107
	xor-int v118, v5, v127
	move-wide/from16 v7, v249
	const-wide v3, 0x718c0999f5bf5ef3L
	div-double/2addr v3, v7
	shl-int v151, v142, v96
	or-int v72, v59, v25
	float-to-long v9, v1
	rem-float v63, v145, v107
	and-int v118, v28, v154
	int-to-float v10, v2
	const-wide v3, 0x9b3c14f0c64b7986L
	sub-long/2addr v13, v3
	or-long/2addr v13, v3
	sub-double v68, v249, v7
	long-to-int v4, v3
	or-int/lit8 v2, v2, 99
	div-int/2addr v5, v2
	int-to-short v8, v2
	sub-int v166, v59, v199
	sub-double v38, v124, v249
	int-to-byte v14, v0
	and-int v237, v177, v34
	sub-int v177, v81, v192
	const-wide v7, 0xaa7259ddc59ddda9L
	const-wide v7, 0x77585d0ab40ec6aaL
	const-wide v0, 0x3c580f4d82f0f443L
	div-double/2addr v0, v7
	shr-int/2addr v14, v4
	div-float v170, v210, v197
	add-long v250, v181, v208
	move/from16 v4, v160
	rem-float/2addr v4, v10
	ushr-int/2addr v5, v2
	add-float v181, v242, v160
	or-int v220, v254, v31
	rem-double/2addr v0, v7
	xor-int v74, v51, v89
	shr-long v60, v226, v151
	int-to-float v15, v14
	or-int/lit8 v170, v230, 38
	move-wide/from16 v7, v178
	long-to-double v13, v7
	and-int/2addr v2, v5
	xor-int/lit16 v0, v5, 22308
	long-to-float v4, v7
	mul-int/2addr v0, v2
	and-int v101, v174, v59
	not-int v11, v2
	shr-long v55, v53, v31
	shr-int/2addr v0, v2
	const-wide v5, 0xb98aab2a8f273550L
	or-long/2addr v5, v7
	and-long/2addr v5, v7
	and-long v197, v77, v252
	or-int/lit8 v37, v37, 10
	div-int v56, v2, v37
	add-int/lit8 v40, v25, 116
	long-to-float v15, v5
	const-wide v13, 0x232cc058c589c2e6L
	const-wide v13, 0x10a2685aad8d0822L
	const-wide v5, 0x19ff845e11fe3f42L
	div-double/2addr v13, v5
	rem-double/2addr v5, v13
	sub-float v185, v168, v180
	rem-double v110, v124, v216
	or-int/lit8 v97, v150, 109
	xor-int/lit8 v68, v137, -16
	mul-int/lit8 v36, v174, 95
	and-int v91, v230, v154
	neg-int v3, v2
	and-int/2addr v0, v2
	shr-long/2addr v7, v0
	and-int v136, v41, v175
	ushr-int v152, v139, v255
	div-double/2addr v13, v5
	shr-int/2addr v0, v2
	ushr-int/2addr v3, v0
	mul-float/2addr v15, v10
	ushr-long v123, v239, v41
	neg-float v4, v15
	sub-int/2addr v2, v11
	add-float v127, v168, v180
	add-double v104, v216, v134
	rem-double/2addr v5, v13
	move-wide/from16 v2, v53
	add-long/2addr v7, v2
	neg-double v3, v5
	shr-int/2addr v0, v11
	move-wide/from16 v12, v197
	const-wide v250, 268435456L
	or-long v12, v12, v250
	rem-long/2addr v7, v12
	sub-double v55, v3, v186
	float-to-long v0, v15
	mul-int/lit16 v10, v11, 9356
	rem-double/2addr v3, v5
	mul-double v59, v104, v216
	float-to-long v8, v15
	xor-long v184, v53, v250
	mul-double v190, v104, v195
	mul-int/lit16 v14, v10, -17658
	div-double/2addr v5, v3
	int-to-float v5, v11
	shr-long/2addr v12, v11
	and-int v77, v161, v138
	rsub-int/lit8 v34, v40, -45
	div-int/lit8 v184, v72, 80
	or-int v173, v220, v81
	add-long/2addr v8, v0
	add-double v77, v190, v38
	or-int/lit8 v11, v11, 53
	rem-int/2addr v10, v11
	ushr-int/lit8 v88, v212, 101
	shr-int v14, v255, v14
	long-to-int v2, v12
	int-to-long v9, v11
	neg-long v6, v12
	or-long v16, v0, v9
	mul-int/2addr v11, v2
	move-wide/from16 v6, v195
	rem-double/2addr v3, v6
	add-double v46, v6, v38
	or-int/2addr v14, v11
	add-double/2addr v6, v3
	mul-long v217, v9, v53
	rem-double/2addr v3, v6
	shl-int/lit8 v182, v129, -63
	shl-long/2addr v9, v2
	ushr-int/2addr v11, v2
	and-int v203, v96, v14
	sub-int/2addr v2, v11
	and-long/2addr v12, v9
	rem-double v15, v171, v59
	float-to-long v13, v5
	rsub-int/lit8 v65, v231, 107
	xor-long/2addr v9, v13
	const v3, 0x49a95382
	rem-float/2addr v5, v3
	xor-long/2addr v9, v0
	rem-float/2addr v3, v5
	or-int/lit8 v11, v11, 21
	div-int/2addr v2, v11
	mul-int/lit8 v206, v184, -123
	mul-float v29, v210, v58
	float-to-int v12, v3
	shr-long v70, v75, v228
	sub-double v2, v46, v186
	long-to-float v4, v9
	or-long/2addr v0, v13
	shl-int v114, v142, v163
	int-to-long v6, v12
	or-int v230, v138, v152
	ushr-int/2addr v11, v12
	mul-float v77, v107, v4
	sub-double/2addr v15, v2
	not-int v14, v11
	float-to-long v15, v5
	shl-long/2addr v6, v12
	const-wide v6, 0x5f83387494be02e2L
	div-double/2addr v2, v6
	or-int/lit8 v12, v12, 101
	rem-int/2addr v11, v12
	const-wide v178, 4096L
	or-long v42, v42, v178
	div-long v236, v70, v42
	add-float v205, v168, v94
	int-to-long v11, v11
	and-long v118, v236, v9
	ushr-int v230, v152, v51
	sub-long v73, v197, v42
	neg-long v11, v11
	xor-long v22, v123, v66
	mul-double v51, v190, v110
	float-to-int v8, v4
	add-long v184, v221, v239
	shr-long/2addr v0, v8
	rsub-int v7, v14, -15016
	shr-long/2addr v0, v8
	or-int/lit8 v249, v98, -71
	int-to-byte v3, v8
	move-wide/from16 v9, v134
	double-to-int v4, v9
	or-int/lit16 v8, v4, -27300
	shl-int v148, v166, v137
	add-double v49, v55, v171
	xor-int/2addr v14, v8
	xor-int/lit8 v244, v150, -126
	shl-int v165, v173, v163
	sub-long v232, v66, v250
	add-long/2addr v15, v0
	or-long v232, v208, v236
	add-int v245, v201, v7
	and-long/2addr v11, v0
	add-int v243, v139, v143
	or-int/2addr v3, v8
	move/from16 v11, v261
	add-float/2addr v5, v11
	sub-double v44, v110, v171
	and-int v144, v129, v82
	int-to-float v12, v3
	double-to-long v5, v9
	xor-int/lit8 v127, v211, -97
	and-int v149, v101, v115
	add-int v94, v138, v206
	const-wide v13, 0xeff45e388f3edbaaL
	sub-double/2addr v9, v13
	rem-double/2addr v13, v9
	or-int/lit8 v29, v7, -94
	rem-float v126, v200, v225
	xor-int v92, v177, v158
	sub-double v35, v38, v190
	xor-long/2addr v0, v15
	or-int/lit8 v211, v211, 13
	div-int v167, v40, v211
	and-long/2addr v15, v5
	mul-float/2addr v11, v12
	shl-int/2addr v3, v4
	mul-int/lit8 v92, v84, 55
	rsub-int v1, v8, 26395
	double-to-long v15, v13
	ushr-long v134, v178, v139
	sub-double/2addr v13, v9
	sub-float v25, v181, v205
	add-double/2addr v13, v9
	mul-double v237, v55, v190
	shr-long v131, v217, v152
	and-long/2addr v15, v5
	and-int v196, v84, v91
	rem-int/lit8 v68, v81, 24
	div-float v187, v12, v145
	mul-float v134, v77, v107
	or-long/2addr v5, v15
	ushr-int v98, v231, v247
	sub-int v87, v243, v133
	ushr-int v23, v98, v194
	neg-float v1, v11
	neg-float v0, v1
	add-int v188, v82, v174
	int-to-byte v13, v3
	int-to-char v5, v7
	neg-double v0, v9
	or-int/2addr v3, v8
	or-int/lit8 v4, v4, 74
	div-int/2addr v7, v4
	mul-float v71, v200, v12
	sub-float v205, v187, v134
	add-int/lit8 v213, v88, -125
	rem-double v130, v171, v9
	neg-double v9, v9
	ushr-long/2addr v15, v4
	or-int/lit8 v7, v7, 100
	rem-int/2addr v4, v7
	add-float/2addr v12, v11
	mul-float v233, v126, v225
	div-float v0, v234, v180
	add-float v97, v71, v187
	rsub-int/lit8 v236, v3, 118
	shr-int v144, v91, v65
	float-to-double v13, v12
	ushr-int/2addr v4, v7
	rsub-int v14, v3, -14641
	long-to-double v4, v15
	const-wide v1, 0x2fc52ee6eee08669L
	add-long/2addr v15, v1
	or-int/lit8 v3, v3, 65
	div-int/2addr v8, v3
	add-int/2addr v3, v14
	neg-float v14, v0
	rem-int/lit8 v205, v89, 60
	or-int/lit8 v0, v90, 113
	or-int/lit16 v11, v0, -13751
	rem-float v206, v234, v134
	xor-int/2addr v7, v0
	not-long v3, v1
	float-to-long v4, v12
	rem-int/lit8 v42, v28, -61
	int-to-char v2, v11
	ushr-int v56, v192, v194
	ushr-int/lit8 v222, v94, 19
	shl-int v242, v112, v211
	long-to-float v7, v4
	div-int/lit8 v161, v203, 6
	neg-float v8, v12
	not-int v12, v11
	shl-int v149, v150, v85
	long-to-double v9, v15
	mul-long/2addr v4, v15
	neg-double v1, v9
	rem-double/2addr v9, v1
	const-wide v208, 512L
	or-long v75, v75, v208
	rem-long v152, v66, v75
	or-int/2addr v0, v11
	int-to-byte v13, v0
	int-to-short v6, v0
	shl-long/2addr v15, v6
	mul-long v104, v226, v4
	or-int/lit8 v159, v159, 53
	div-int v192, v212, v159
	or-int/lit8 v13, v13, 91
	rem-int/2addr v12, v13
	or-long v23, v73, v4
	or-int/lit16 v10, v13, 11922
	xor-int/lit8 v146, v96, 27
	add-long v146, v152, v123
	div-float v80, v234, v8
	ushr-int/lit8 v81, v136, -120
	double-to-int v15, v1
	mul-float/2addr v8, v7
	shr-int/2addr v12, v13
	move-wide/from16 v14, v223
	xor-long/2addr v14, v4
	xor-long v222, v53, v223
	xor-int/lit16 v7, v12, -10743
	const v12, 0xc2d3b38f
	add-float/2addr v8, v12
	const-wide v184, 4194304L
	or-long v4, v4, v184
	rem-long/2addr v14, v4
	int-to-float v9, v10
	double-to-float v12, v1
	rsub-int v15, v10, 26912
	add-int/2addr v7, v13
	neg-double v6, v1
	long-to-int v1, v4
	int-to-short v9, v10
	long-to-double v1, v4
	int-to-long v13, v0
	rem-float/2addr v12, v8
	rem-int/lit16 v3, v0, 30206
	float-to-double v14, v8
	mul-float v219, v107, v77
	xor-long v232, v66, v23
	rsub-int v0, v0, -374
	shr-int v179, v255, v159
	neg-double v11, v14
	and-int/2addr v9, v0
	shl-long v225, v4, v179
	mul-int/lit8 v172, v236, 117
	int-to-float v10, v9
	sub-float/2addr v8, v10
	or-int v242, v177, v165
	shr-long v86, v152, v155
	div-double/2addr v11, v14
	add-long v47, v73, v184
	const-wide v225, 2048L
	or-long v86, v86, v225
	div-long v51, v184, v86
	sub-int v26, v37, v165
	int-to-byte v1, v3
	xor-long v114, v75, v184
	mul-int/lit8 v55, v40, -72
	add-long v208, v51, v222
	sub-double v41, v14, v237
	int-to-double v14, v3
	or-long v226, v51, v225
	add-double v86, v41, v44
	add-int v243, v151, v94
	rsub-int v13, v1, 15870
	xor-int/2addr v0, v1
	shl-int/lit8 v70, v212, -92
	long-to-double v5, v4
	xor-int/2addr v0, v9
	move-wide/from16 v10, v104
	const-wide v8, 0xf0f5eb5f24ff2335L
	const-wide v250, 4096L
	or-long v8, v8, v250
	div-long/2addr v10, v8
	sub-int v225, v142, v138
	and-long/2addr v10, v8
	and-long/2addr v10, v8
	mul-int/lit8 v67, v165, -42
	div-int/lit8 v197, v82, 53
	const-wide v51, 8192L
	or-long v226, v226, v51
	rem-long v19, v184, v226
	mul-long/2addr v8, v10
	div-float v84, v63, v181
	double-to-long v0, v14
	mul-int v141, v81, v167
	mul-int/lit16 v2, v3, 32761
	xor-int/2addr v13, v3
	mul-float v249, v210, v160
	rsub-int/lit8 v30, v142, 111
	and-int/2addr v3, v2
	rsub-int/lit8 v240, v182, -112
	mul-long/2addr v8, v0
	add-int/lit16 v9, v2, -29994
	add-long/2addr v0, v10
	and-int/lit8 v94, v13, -90
	mul-int v132, v199, v173
	long-to-int v10, v0
	int-to-long v12, v2
	rsub-int/lit8 v88, v255, -88
	long-to-int v13, v0
	or-int/lit16 v4, v9, -8897
	shr-long/2addr v0, v10
	shr-long/2addr v0, v4
	xor-int v109, v165, v132
	or-int v108, v81, v151
	shl-int/2addr v4, v2
	const-wide v11, 0x9ec12c7f82f4ab97L
	sub-long/2addr v0, v11
	shl-int/lit8 v125, v108, 98
	add-double v107, v49, v237
	and-int/2addr v10, v2
	and-int/2addr v2, v3
	add-int/lit16 v4, v13, -7873
	shr-int/lit8 v119, v155, -123
	ushr-long v200, v11, v98
	sub-long/2addr v0, v11
	shl-int v147, v89, v248
	add-long/2addr v0, v11
	shl-long v192, v232, v150
	and-int v204, v225, v13
	mul-double/2addr v14, v5
	move/from16 v15, v181
	move/from16 v13, v145
	mul-float/2addr v13, v15
	shl-int v191, v161, v255
	shr-long v9, v104, v137
	or-int/lit8 v3, v3, 3
	div-int/2addr v2, v3
	rem-int/lit16 v11, v4, -25034
	div-float v184, v187, v180
	shr-int v203, v242, v101
	mul-float v12, v219, v210
	mul-float v112, v145, v97
	xor-int/2addr v4, v2
	const-wide v2, 0x27900d5bf5349c63L
	add-double/2addr v2, v5
	shl-int v18, v205, v136
	mul-float/2addr v15, v12
	xor-int/lit16 v9, v4, 32576
	shr-int/lit8 v113, v166, -65
	float-to-int v5, v12
	long-to-float v6, v0
	or-int/lit16 v12, v5, -25532
	mul-int/2addr v9, v11
	div-int/lit16 v11, v5, 445
	const-wide v3, 0x902ad3f92cd5aa02L
	move-wide/from16 v8, v38
	add-double/2addr v3, v8
	div-float v231, v234, v126
	mul-long v114, v23, v217
	const-wide v2, 0xd8518dc0163ff7caL
	const-wide v252, 268435456L
	or-long v2, v2, v252
	rem-long/2addr v0, v2
	neg-long v10, v2
	float-to-double v13, v13
	div-float/2addr v6, v15
	not-long v9, v10
	or-int/lit16 v6, v12, -24620
	neg-long v4, v9
	ushr-int v48, v151, v202
	and-long/2addr v2, v0
	mul-float v25, v181, v84
	const-wide v75, 131072L
	or-long v208, v208, v75
	div-long v88, v200, v208
	ushr-long v206, v222, v92
	and-int/lit16 v10, v12, 4981
	const-wide v0, 16777216L
	or-long v4, v4, v0
	rem-long/2addr v0, v4
	or-int/lit8 v125, v125, 16
	div-int v130, v166, v125
	mul-int/lit16 v7, v6, 23004
	sub-int/2addr v10, v12
	int-to-short v9, v7
	or-int/2addr v9, v6
	mul-long v37, v53, v73
	int-to-double v0, v9
	sub-double v3, v49, v86
	double-to-int v2, v3
	rem-int/lit16 v14, v2, 32681
	int-to-long v4, v2
	float-to-int v0, v15
	int-to-byte v1, v10
	const-wide v0, 0x30cd4970658ff2b9L
	move-wide/from16 v10, v41
	mul-double/2addr v10, v0
	not-long v1, v4
	xor-long v224, v252, v37
	sub-float v248, v249, v219
	neg-long v0, v4
	or-int v247, v98, v154
	const-wide v224, 8L
	or-long v0, v0, v224
	div-long/2addr v4, v0
	or-int/lit8 v12, v12, 36
	div-int/2addr v9, v12
	shl-int v86, v30, v9
	mul-int/lit16 v7, v12, -9295
	shl-long v134, v75, v129
	xor-int v71, v214, v26
	mul-int/lit16 v3, v14, 19582
	not-long v5, v4
	ushr-long v230, v226, v228
	rem-double v86, v10, v44
	add-float v166, v248, v80
	xor-long v217, v208, v134
	or-int/lit8 v161, v26, 75
	const-wide v104, 4194304L
	or-long v5, v5, v104
	rem-long/2addr v0, v5
	or-int/lit8 v34, v34, 82
	div-int v243, v55, v34
	or-int/lit8 v204, v204, 10
	rem-int v70, v81, v204
	int-to-byte v4, v12
	or-int/lit16 v2, v3, -27865
	shr-int/2addr v14, v3
	xor-int v160, v133, v148
	div-int/lit8 v55, v214, 119
	double-to-float v13, v10
	ushr-long/2addr v0, v14
	rsub-int v13, v4, -17660
	or-long v56, v217, v152
	rem-int/lit16 v13, v4, -17849
	sub-long v99, v232, v217
	xor-int/lit8 v99, v125, 63
	add-int/lit8 v218, v150, -69
	ushr-long v4, v206, v7
	add-long/2addr v0, v4
	or-int/lit8 v12, v12, 63
	rem-int/2addr v14, v12
	const-wide v23, 33554432L
	or-long v0, v0, v23
	rem-long/2addr v4, v0
	or-int/lit8 v106, v106, 17
	rem-int v156, v9, v106
	mul-int v198, v132, v156
	const-wide v6, 0xa13d70cc28337356L
	add-double/2addr v10, v6
	sub-float v184, v120, v77
	add-int/2addr v14, v3
	or-int/lit8 v9, v9, 5
	rem-int/2addr v12, v9
	add-int v17, v48, v138
	rem-double/2addr v10, v6
	div-float v136, v126, v97
	double-to-float v3, v10
	const-wide v104, 2048L
	or-long v4, v4, v104
	div-long/2addr v0, v4
	const-wide v23, 16777216L
	or-long v4, v4, v23
	rem-long/2addr v0, v4
	double-to-long v2, v10
	add-double v60, v6, v237
	add-int/2addr v14, v12
	add-double v4, v86, v6
	int-to-double v7, v13
	add-int/lit16 v15, v9, -22090
	or-long v92, v224, v88
	shr-long v175, v19, v103
	add-float v215, v80, v184
	ushr-int v13, v15, v242
	mul-int v6, v205, v182
	rem-double v244, v60, v7
	sub-double/2addr v10, v4
	sub-long/2addr v2, v0
	not-long v8, v0
	neg-int v12, v6
	const v4, 0xd094452a
	float-to-long v11, v4
	or-int/lit8 v255, v255, 92
	rem-int v53, v204, v255
	rem-float v189, v166, v77
	add-double v6, v41, v237
	or-int/2addr v13, v15
	mul-long/2addr v2, v0
	ushr-long v160, v114, v199
	long-to-float v9, v2
	shl-long/2addr v2, v15
	sub-int/2addr v13, v15
	or-long/2addr v11, v2
	and-long/2addr v0, v2
	or-int/lit16 v2, v13, -6703
	or-int/lit8 v182, v85, -125
	and-int v55, v148, v144
	mul-int/2addr v15, v14
	mul-double v187, v44, v60
	rem-int/lit16 v9, v15, 12833
	sub-double v12, v86, v41
	or-long v245, v92, v73
	shr-long v251, v114, v30
	long-to-double v15, v0
	const-wide v5, 0x5483b3a96657e209L
	add-long/2addr v0, v5
	or-int/lit8 v2, v2, 43
	div-int/2addr v9, v2
	ushr-long/2addr v0, v2
	shr-long v6, v251, v220
	mul-int/lit16 v15, v9, 24125
	mul-int/2addr v9, v14
	move-wide/from16 v12, v271
	move-wide/from16 v11, v187
	move-wide/from16 v5, v269
	div-double/2addr v11, v5
	shl-long/2addr v0, v2
	long-to-int v4, v0
	const v3, 0xb531a0e
	const v7, 0x36c4bf6f
	div-float/2addr v3, v7
	div-float v159, v248, v215
	div-float/2addr v3, v7
	long-to-double v13, v0
	rem-double/2addr v5, v11
	ushr-long/2addr v0, v15
	int-to-char v14, v4
	ushr-long/2addr v0, v4
	shl-int/lit8 v84, v154, -3
	float-to-int v3, v3
	rem-float v219, v80, v234
	long-to-double v12, v0
	move/from16 v7, v112
	move/from16 v6, v260
	sub-float/2addr v7, v6
	div-double v34, v60, v49
	add-long v207, v0, v88
	sub-int/2addr v2, v4
	shr-int/2addr v2, v3
	float-to-long v5, v6
	div-float v37, v210, v58
	ushr-int/2addr v2, v3
	mul-long v60, v207, v160
	and-int/2addr v3, v9
	mul-int/2addr v3, v9
	neg-long v8, v0
	double-to-long v9, v12
	sub-long v244, v232, v160
	shr-int v245, v14, v4
	float-to-double v12, v7
	rem-double v210, v49, v86
	float-to-int v11, v7
	add-double v208, v34, v44
	float-to-int v3, v7
	const-wide v60, 32L
	or-long v222, v222, v60
	div-long v208, v226, v222
	sub-int/2addr v15, v2
	and-int/lit8 v182, v84, -66
	sub-long/2addr v5, v0
	or-long v79, v19, v222
	mul-double v99, v34, v110
	not-long v12, v0
	rem-double v223, v237, v99
	div-double v30, v107, v49
	rem-int/lit16 v7, v4, -17824
	or-int/lit8 v163, v163, 66
	div-int v6, v228, v163
	mul-int/lit8 v80, v155, 72
	shr-long/2addr v9, v15
	move-wide/from16 v5, v107
	move-wide/from16 v5, v269
	move-wide/from16 v15, v86
	sub-double/2addr v15, v5
	or-int/lit8 v68, v68, 12
	div-int v203, v254, v68
	mul-long/2addr v0, v12
	const-wide v208, 16384L
	or-long v0, v0, v208
	rem-long/2addr v12, v0
	rsub-int v12, v7, 21281
	mul-float v72, v136, v126
	shl-int/2addr v14, v3
	long-to-float v11, v0
	neg-float v0, v11
	rsub-int/lit8 v130, v179, 71
	and-int/lit16 v2, v4, 23175
	rem-double v161, v237, v99
	mul-float v235, v184, v112
	shl-int/lit8 v146, v228, -50
	add-float v18, v37, v249
	sub-float v66, v63, v181
	shr-int/lit8 v87, v174, 52
	or-int v86, v17, v85
	shr-int v82, v129, v220
	ushr-long v123, v226, v202
	ushr-int v63, v163, v119
	sub-int/2addr v7, v14
	rsub-int v10, v14, -29725
	ushr-int/lit8 v233, v4, 63
	move-wide/from16 v1, v134
	not-long v0, v1
	mul-int/2addr v4, v3
	shr-int/lit8 v99, v103, 101
	float-to-int v14, v11
	or-int/lit8 v14, v14, 26
	rem-int/2addr v10, v14
	mul-double/2addr v15, v5
	ushr-long/2addr v0, v4
	sub-double/2addr v15, v5
	rsub-int v13, v3, 19753
	xor-int/lit8 v76, v63, 46
	int-to-double v9, v13
	and-int v38, v91, v133
	move/from16 v4, v136
	sub-float/2addr v11, v4
	neg-long v1, v0
	rem-float/2addr v4, v11
	xor-int v98, v196, v149
	add-double/2addr v9, v15
	const-wide v8, 0x94b9f59cab46455bL
	const-wide v8, 2048L
	or-long v8, v8, v8
	rem-long/2addr v1, v8
	or-int/lit8 v246, v17, 13
	float-to-long v4, v4
	shl-int v39, v137, v141
	sub-float v224, v11, v180
	float-to-int v10, v11
	const-wide v14, 0x58f6d392f36ca244L
	const-wide v7, 0xf4e0edfd6e84e264L
	mul-double/2addr v14, v7
	int-to-char v10, v13
	long-to-float v14, v1
	xor-long/2addr v4, v1
	add-int/lit8 v48, v109, -78
	xor-int/lit16 v6, v13, 479
	xor-int v128, v218, v65
	add-int/2addr v6, v3
	mul-long v159, v200, v88
	rem-float v232, v72, v37
	shl-int/lit8 v22, v96, -10
	and-int v110, v40, v82
	int-to-long v6, v13
	mul-int/2addr v3, v12
	move-wide/from16 v8, v269
	const-wide v12, 0x144215228de7ecffL
	mul-double/2addr v12, v8
	add-long v88, v73, v159
	sub-int v135, v70, v177
	sub-long/2addr v6, v1
	sub-double/2addr v12, v8
	shr-int v59, v101, v254
	xor-long/2addr v6, v4
	rem-int/lit16 v7, v3, 31446
	const-wide v123, 2048L
	or-long v1, v1, v123
	rem-long/2addr v4, v1
	mul-double v172, v107, v8
	xor-int v132, v163, v240
	shr-int/2addr v7, v3
	xor-int/2addr v10, v3
	shl-long v8, v56, v191
	or-int/lit8 v7, v7, 91
	div-int/2addr v10, v7
	const-wide v56, 65536L
	or-long v226, v226, v56
	rem-long v46, v123, v226
	add-float v59, v166, v120
	float-to-double v3, v14
	rem-double/2addr v12, v3
	or-int/lit8 v7, v7, 87
	rem-int/2addr v10, v7
	or-int/lit8 v17, v17, 80
	div-int v1, v96, v17
	mul-int/2addr v1, v10
	shr-int v97, v103, v144
	xor-int/2addr v7, v10
	ushr-int/2addr v10, v1
	shr-long/2addr v8, v1
	or-int/2addr v1, v7
	mul-long v133, v208, v200
	shr-int v174, v204, v199
	sub-double v169, v210, v12
	int-to-byte v10, v1
	add-float/2addr v11, v14
	div-int/lit16 v13, v10, 25932
	and-int/lit16 v4, v7, -8119
	const-wide v6, 0x19499a3fb291c691L
	add-long/2addr v8, v6
	int-to-char v13, v13
	mul-int/lit16 v9, v1, 28061
	rem-float/2addr v14, v11
	move-wide/from16 v10, v187
	const-wide v1, 0xc4313db4cd3bee6cL
	div-double/2addr v10, v1
	xor-int v161, v22, v94
	int-to-char v9, v4
	sub-long v212, v133, v88
	double-to-float v11, v10
	int-to-float v11, v9
	or-int/lit8 v147, v147, 17
	div-int v148, v132, v147
	or-int/lit16 v0, v9, -30262
	rem-float/2addr v14, v11
	rem-int/lit16 v0, v0, -20847
	move-wide/from16 v11, v92
	const-wide v133, 2L
	or-long v11, v11, v133
	rem-long/2addr v6, v11
	ushr-long v177, v230, v198
	xor-int v217, v17, v205
	move-wide/from16 v7, v172
	add-double/2addr v7, v1
	int-to-long v13, v0
	shr-int/lit8 v31, v142, -10
	shr-int/2addr v4, v9
	const v1, 0x395a3b7e
	neg-float v1, v1
	int-to-short v12, v9
	xor-int/lit8 v62, v65, 59
	neg-int v12, v12
	int-to-char v12, v4
	rsub-int v13, v0, -24649
	add-int/lit16 v8, v0, 865
	or-int/lit8 v4, v4, 32
	rem-int/2addr v0, v4
	ushr-int/lit8 v6, v255, 27
	const-wide v175, 2097152L
	or-long v251, v251, v175
	rem-long v37, v123, v251
	rem-float v211, v18, v249
	xor-int/lit16 v3, v4, -24767
	int-to-char v2, v0
	const-wide v14, 0x63ef6ad506b0fad6L
	move-wide/from16 v0, v187
	sub-double/2addr v0, v14
	const-wide v15, 0x2df8c1580117fc69L
	const-wide v11, 0x18c06b5c9698137bL
	const-wide v208, 65536L
	or-long v11, v11, v208
	rem-long/2addr v15, v11
	int-to-float v11, v13
	const v15, 0xa1042f7a
	rem-float/2addr v11, v15
	div-int/lit16 v14, v2, -7517
	double-to-float v1, v0
	move-wide/from16 v9, v34
	double-to-float v2, v9
	div-double v137, v172, v49
	shr-int v136, v199, v220
	or-int/lit16 v15, v4, 17280
	move-wide/from16 v4, v269
	div-double/2addr v4, v9
	add-double/2addr v4, v9
	mul-double v188, v172, v137
	mul-int v71, v28, v31
	add-int/2addr v8, v13
	xor-long v163, v23, v251
	add-float v198, v211, v1
	add-float/2addr v1, v2
	not-int v14, v3
	and-int/lit16 v14, v15, 26535
	rem-float/2addr v11, v1
	add-int/lit16 v11, v13, -2758
	mul-int/lit16 v8, v14, 28564
	shl-int v144, v86, v103
	mul-int/lit8 v241, v113, 17
	move-wide/from16 v14, v263
	move-wide/from16 v6, v23
	const-wide v226, 524288L
	or-long v14, v14, v226
	div-long/2addr v6, v14
	mul-float v57, v168, v235
	ushr-int v169, v48, v203
	xor-long v104, v92, v123
	or-int/lit16 v14, v3, -26045
	add-int/lit16 v4, v8, -28931
	shl-int/lit8 v118, v65, 20
	mul-int/2addr v4, v14
	shl-int/2addr v13, v11
	int-to-long v11, v13
	add-int/2addr v3, v13
	double-to-float v0, v9
	float-to-double v4, v0
	or-int/lit8 v209, v55, 108
	add-double v202, v107, v44
	shr-int/lit8 v24, v110, -26
	float-to-long v1, v1
	ushr-int/lit8 v34, v204, 63
	double-to-int v6, v4
	long-to-int v7, v1
	not-long v8, v1
	add-long/2addr v11, v1
	move/from16 v9, v232
	rem-float/2addr v0, v9
	mul-int/lit8 v105, v129, -113
	or-long/2addr v1, v11
	and-long v25, v11, v163
	rsub-int/lit8 v153, v196, 106
	xor-long v219, v92, v1
	ushr-long v72, v46, v148
	and-int/lit16 v6, v14, 29460
	or-int/lit16 v2, v6, 30148
	rsub-int/lit8 v190, v94, -35
	xor-int v2, v128, v6
	not-int v13, v7
	shr-int/2addr v13, v3
	move-wide/from16 v3, v51
	const-wide v159, 2097152L
	or-long v3, v3, v159
	rem-long/2addr v11, v3
	and-int v143, v151, v76
	and-int/lit8 v9, v28, 114
	and-long v75, v88, v133
	shl-long/2addr v3, v7
	int-to-char v1, v9
	or-long/2addr v3, v11
	move-wide/from16 v4, v172
	move-wide/from16 v10, v41
	add-double/2addr v10, v4
	int-to-long v14, v1
	int-to-double v15, v7
	and-int/lit16 v9, v6, 18100
	move/from16 v6, v18
	div-float/2addr v6, v0
	add-double v79, v188, v237
	mul-double v113, v15, v237
	mul-int/lit16 v6, v7, 5670
	int-to-long v7, v1
	move/from16 v5, v0
	add-float/2addr v5, v0
	float-to-long v6, v0
	add-int v227, v39, v125
	shl-long v76, v88, v40
	add-float/2addr v5, v0
	add-double/2addr v10, v15
	add-double v82, v202, v107
	add-float/2addr v0, v5
	int-to-byte v4, v13
	or-long v14, v219, v19
	const-wide v72, 33554432L
	or-long v123, v123, v72
	div-long v12, v37, v123
	or-int/2addr v4, v1
	mul-long/2addr v6, v12
	not-int v12, v4
	const-wide v192, 67108864L
	or-long v123, v123, v192
	div-long v134, v92, v123
	xor-int/lit16 v4, v4, -10539
	double-to-long v5, v10
	or-int/lit8 v29, v29, 65
	rem-int v233, v174, v29
	rsub-int/lit8 v20, v31, -109
	const-wide v92, 67108864L
	or-long v14, v14, v92
	div-long/2addr v5, v14
	neg-float v9, v0
	int-to-long v2, v2
	ushr-int/lit8 v60, v167, -18
	const-wide v123, 131072L
	or-long v14, v14, v123
	div-long/2addr v2, v14
	mul-long/2addr v5, v2
	const-wide v46, 65536L
	or-long v5, v5, v46
	div-long/2addr v14, v5
	and-int/lit8 v8, v12, 54
	neg-long v4, v5
	rsub-int v3, v8, 11617
	not-int v7, v3
	xor-long v13, v134, v46
	or-int/lit8 v85, v105, -79
	or-int/lit8 v203, v24, 97
	const-wide v92, 128L
	or-long v25, v25, v92
	rem-long v185, v163, v25
	add-int/lit16 v4, v12, 20592
	int-to-byte v15, v7
	const-wide v15, 0xa05ce726f7d4a350L
	add-long/2addr v15, v13
	int-to-double v13, v8
	add-int/lit8 v21, v247, 0
	int-to-char v5, v8
	shl-long v174, v175, v62
	rem-int/lit16 v15, v5, 24168
	mul-int/lit8 v227, v55, 119
	or-int/lit16 v0, v7, -19379
	float-to-double v14, v9
	mul-int/2addr v5, v0
	neg-double v5, v10
	xor-int/lit8 v86, v167, 76
	mul-double v132, v5, v137
	move-wide/from16 v0, v263
	move-wide/from16 v11, v72
	sub-long/2addr v0, v11
	sub-int/2addr v3, v8
	int-to-long v15, v7
	float-to-double v0, v9
	double-to-long v4, v5
	and-int/lit16 v0, v3, 16905
	div-int/lit8 v113, v101, 58
	sub-long v174, v230, v192
	int-to-short v12, v8
	const-wide v2, 0xbd9288f45e5af10L
	double-to-int v8, v2
	double-to-float v7, v2
	int-to-char v1, v8
	const-wide v185, 262144L
	or-long v15, v15, v185
	div-long/2addr v4, v15
	or-int/lit16 v13, v12, 20354
	const-wide v123, 128L
	or-long v4, v4, v123
	rem-long v88, v134, v4
	move-wide/from16 v12, v269
	add-double/2addr v12, v2
	add-long v40, v159, v163
	or-int/lit8 v96, v150, -22
	mul-long/2addr v4, v15
	double-to-long v7, v2
	long-to-float v1, v15
	div-float v246, v126, v66
	shl-long v244, v134, v130
	mul-long/2addr v4, v7
	neg-int v2, v0
	xor-int v154, v165, v199
	rsub-int/lit8 v105, v71, -26
	sub-int/2addr v2, v0
	or-int/lit16 v7, v2, -28845
	add-long/2addr v15, v4
	ushr-long/2addr v4, v7
	add-double v233, v44, v49
	double-to-float v8, v12
	const-wide v230, 2048L
	or-long v4, v4, v230
	rem-long/2addr v15, v4
	float-to-double v3, v8
	or-int/lit8 v229, v142, 12
	sub-int/2addr v2, v0
	neg-int v14, v7
	long-to-double v8, v15
	rem-double/2addr v8, v12
	int-to-long v7, v14
	sub-int v221, v161, v21
	rem-int/lit16 v13, v14, 30349
	or-int v191, v96, v17
	div-int/lit16 v4, v14, -19318
	shr-long v110, v177, v103
	float-to-int v12, v1
	long-to-double v10, v15
	mul-double v107, v237, v79
	neg-long v9, v15
	div-double v216, v172, v44
	and-long/2addr v15, v7
	ushr-long/2addr v7, v14
	move/from16 v7, v18
	add-float/2addr v1, v7
	add-int v89, v96, v63
	move-wide/from16 v0, v233
	const-wide v10, 0x483b4e563a14826L
	rem-double/2addr v10, v0
	long-to-double v15, v15
	int-to-long v6, v12
	const-wide v14, 0x53004e8f2a425236L
	const-wide v46, 16L
	or-long v6, v6, v46
	div-long/2addr v14, v6
	int-to-float v12, v12
	neg-int v0, v13
	mul-float v131, v58, v145
	and-long/2addr v14, v6
	move-wide/from16 v1, v82
	mul-double/2addr v10, v1
	const-wide v244, 536870912L
	or-long v200, v200, v244
	rem-long v27, v244, v200
	div-double/2addr v1, v10
	add-int/lit8 v167, v228, -70
	neg-int v12, v4
	add-double v164, v107, v49
	and-int/lit16 v11, v12, 17330
	xor-long/2addr v14, v6
	const-wide v134, 1048576L
	or-long v219, v219, v134
	div-long v114, v72, v219
	ushr-int v2, v236, v240
	move/from16 v14, v168
	move/from16 v3, v261
	rem-float/2addr v3, v14
	sub-long v56, v251, v185
	move-wide/from16 v11, v92
	sub-long/2addr v11, v6
	neg-int v1, v13
	add-double v124, v237, v44
	shr-int v176, v149, v68
	and-int/2addr v1, v0
	int-to-char v13, v1
	shl-int/lit8 v92, v227, -66
	or-int/lit8 v165, v105, 127
	mul-long/2addr v6, v11
	add-float/2addr v14, v3
	or-int/lit8 v1, v1, 61
	rem-int/2addr v2, v1
	ushr-int/2addr v2, v4
	int-to-long v10, v13
	shr-int/lit8 v26, v247, -106
	int-to-double v9, v1
	move-wide/from16 v12, v216
	sub-double/2addr v9, v12
	int-to-short v11, v2
	sub-float/2addr v14, v3
	add-int/lit8 v68, v167, 61
	sub-int/2addr v1, v0
	xor-int/lit16 v5, v0, -18038
	int-to-double v3, v0
	xor-int/2addr v0, v5
	move-wide/from16 v5, v6
	const-wide v2, 0xa606a9cbec205c83L
	sub-long/2addr v2, v5
	xor-int v151, v218, v94
	xor-int/2addr v11, v1
	shl-int v239, v204, v86
	move/from16 v2, v215
	add-float/2addr v2, v14
	or-int/lit8 v138, v109, 52
	rsub-int v11, v0, 18088
	shr-long v45, v174, v63
	shl-long/2addr v5, v1
	const-wide v230, 2048L
	or-long v230, v230, v230
	rem-long v168, v40, v230
	move-wide/from16 v4, v244
	move-wide/from16 v6, v219
	const-wide v219, 32768L
	or-long v6, v6, v219
	rem-long/2addr v4, v6
	const-wide v177, 65536L
	or-long v56, v56, v177
	rem-long v75, v219, v56
	double-to-float v0, v12
	and-int/2addr v11, v1
	and-long/2addr v6, v4
	long-to-double v14, v6
	shl-int v185, v105, v179
	neg-long v3, v6
	and-long/2addr v6, v3
	xor-int/lit16 v2, v11, -12707
	int-to-long v6, v2
	rem-float v185, v166, v181
	float-to-long v0, v0
	sub-float v241, v211, v224
	int-to-short v12, v2
	long-to-int v11, v0
	add-long/2addr v6, v0
	sub-long/2addr v0, v3
	shr-long/2addr v3, v12
	mul-int/2addr v11, v12
	move/from16 v6, v261
	const v13, 0x21e3135f
	add-float/2addr v6, v13
	sub-double v170, v132, v79
	add-int/2addr v12, v11
	double-to-long v6, v9
	float-to-double v14, v13
	long-to-double v8, v3
	div-double v156, v172, v8
	mul-double/2addr v8, v14
	long-to-float v10, v6
	xor-int/2addr v2, v12
	rem-double v159, v8, v172
	neg-int v14, v12
	or-int/lit8 v242, v242, 19
	rem-int v133, v85, v242
	float-to-int v12, v10
	add-int/2addr v11, v2
	int-to-short v3, v11
	sub-int v45, v158, v119
	not-int v9, v14
	mul-int v103, v204, v45
	or-long/2addr v6, v0
	shr-int/2addr v2, v14
	sub-double v254, v82, v216
	div-float/2addr v10, v13
	const-wide v168, 4194304L
	or-long v40, v40, v168
	rem-long v62, v168, v40
	xor-int/lit8 v49, v12, -94
	or-int/2addr v12, v9
	rem-float v76, v112, v58
	move-wide/from16 v9, v188
	neg-double v13, v9
	add-float v214, v241, v181
	mul-long/2addr v6, v0
	mul-long v160, v0, v37
	div-float v169, v235, v214
	add-int/lit8 v156, v68, 100
	mul-double/2addr v13, v9
	or-long/2addr v6, v0
	shr-long/2addr v0, v11
	shr-int/lit8 v66, v197, 103
	div-double v65, v107, v124
	neg-long v14, v6
	rem-double v94, v9, v65
	sub-double v201, v94, v188
	ushr-int/2addr v11, v12
	double-to-float v12, v9
	add-double v129, v9, v82
	neg-int v8, v3
	or-int v5, v22, v2
	div-double v109, v201, v82
	or-int/lit8 v13, v209, 79
	const v9, 0x2cb7f4f1
	sub-float/2addr v9, v12
	div-float/2addr v12, v9
	or-int/lit16 v5, v5, 14629
	mul-int/lit16 v14, v8, -3118
	rem-float/2addr v9, v12
	rsub-int/lit8 v32, v143, 60
	rsub-int/lit8 v223, v138, 39
	sub-int v192, v218, v24
	move-wide/from16 v1, v82
	neg-double v2, v1
	move-wide/from16 v8, v134
	xor-long/2addr v8, v6
	int-to-short v10, v11
	int-to-char v15, v13
	and-long/2addr v8, v6
	or-int/lit8 v14, v14, 42
	rem-int/2addr v15, v14
	move/from16 v15, v249
	div-float/2addr v12, v15
	div-int/lit16 v3, v5, 21646
	and-int/lit16 v7, v13, 31852
	move-wide/from16 v2, v201
	move-wide/from16 v15, v94
	div-double/2addr v15, v2
	int-to-byte v7, v13
	int-to-short v11, v13
	add-double/2addr v15, v2
	div-float v31, v18, v232
	div-float v57, v31, v248
	xor-int v71, v176, v218
	xor-long v34, v27, v251
	mul-int/lit8 v10, v119, -4
	shr-long v243, v160, v87
	float-to-double v10, v12
	shl-int/2addr v14, v5
	rem-double/2addr v2, v15
	shr-int/lit8 v81, v138, 118
	const v3, 0x8449d290
	add-float/2addr v12, v3
	neg-long v14, v8
	const-wide v212, 4194304L
	or-long v8, v8, v212
	rem-long/2addr v14, v8
	shl-long v245, v14, v128
	and-long v228, v62, v114
	int-to-float v1, v13
	float-to-double v5, v1
	xor-long v57, v40, v174
	const-wide v228, 32768L
	or-long v14, v14, v228
	rem-long/2addr v8, v14
	add-int/2addr v13, v7
	or-int/lit8 v156, v156, 98
	div-int v116, v96, v156
	double-to-int v1, v10
	xor-long v39, v8, v251
	shr-long v59, v34, v205
	or-int/lit8 v1, v1, 82
	rem-int/2addr v13, v1
	add-int/2addr v1, v7
	shl-long v64, v230, v90
	or-int/lit8 v189, v45, 42
	add-long/2addr v8, v14
	double-to-long v10, v10
	or-int/lit16 v15, v13, 25617
	ushr-int/2addr v7, v15
	int-to-byte v5, v1
	mul-long/2addr v8, v10
	and-int/lit16 v13, v1, -21003
	sub-long v242, v72, v243
	xor-int v252, v1, v96
	int-to-double v8, v15
	div-float/2addr v3, v12
	mul-int v49, v247, v141
	and-long v161, v228, v134
	shl-int v64, v191, v141
	div-int/lit8 v195, v29, -45
	xor-int/lit8 v113, v113, 1
	and-int/lit8 v189, v191, -128
	or-long v90, v57, v161
	shr-int/lit8 v199, v113, 38
	rsub-int v12, v1, -23147
	rsub-int/lit8 v169, v176, 94
	int-to-char v6, v15
	const-wide v11, 0x58843078d46ab415L
	sub-double/2addr v8, v11
	const-wide v14, 0x772e99e2cdfac77aL
	shl-long/2addr v14, v1
	shr-long v88, v62, v143
	int-to-float v10, v6
	int-to-byte v14, v7
	const-wide v5, 0x4cede99f4b26133dL
	shl-long/2addr v5, v1
	mul-float/2addr v10, v3
	rsub-int/lit8 v121, v113, -53
	mul-int/lit8 v62, v197, -21
	sub-long v89, v177, v228
	long-to-int v11, v5
	xor-long v4, v72, v114
	sub-int/2addr v14, v1
	add-long v218, v51, v72
	not-long v4, v4
	or-int/lit8 v113, v113, 7
	div-int v117, v128, v113
	shr-long v231, v27, v197
	sub-float v91, v211, v120
	add-float v19, v120, v31
	rem-float v45, v224, v131
	xor-int/lit16 v7, v1, 12693
	and-int/lit8 v106, v48, 8
	div-int/lit8 v7, v106, -32
	shl-long v194, v57, v127
	and-int/lit16 v4, v14, -19697
	or-int/2addr v7, v14
	rem-float/2addr v10, v3
	int-to-double v7, v11
	add-int/lit16 v5, v13, -25857
	and-int/lit16 v9, v11, 5062
	add-int/2addr v14, v1
	or-int/lit8 v14, v14, 12
	rem-int/2addr v1, v14
	rem-float v78, v91, v235
	and-int/lit16 v15, v13, 17827
	move-wide/from16 v7, v89
	long-to-int v12, v7
	shl-long/2addr v7, v9
	sub-double v182, v107, v233
	shl-int v61, v24, v29
	rsub-int v3, v5, 668
	or-long v69, v59, v134
	rem-float v182, v215, v19
	div-int/lit8 v100, v189, -91
	or-int/lit8 v5, v5, 44
	rem-int/2addr v4, v5
	ushr-long v253, v27, v15
	int-to-double v10, v1
	long-to-int v8, v7
	add-float v39, v18, v131
	add-int/lit16 v14, v8, -16057
	move/from16 v1, v76
	const v3, 0xbb15678a
	rem-float/2addr v3, v1
	move-wide/from16 v10, v114
	shr-long/2addr v10, v15
	int-to-short v9, v13
	shl-long v95, v194, v227
	const-wide v2, 0xbcfd90a075ea1deeL
	double-to-long v0, v2
	int-to-long v12, v4
	move-wide/from16 v13, v216
	mul-double/2addr v2, v13
	move/from16 v9, v180
	move/from16 v7, v184
	sub-float/2addr v9, v7
	long-to-double v12, v0
	not-int v5, v15
	div-float v172, v120, v19
	or-long v129, v177, v69
	add-double v38, v170, v107
	rem-int/lit16 v14, v5, 24962
	int-to-short v10, v4
	double-to-long v2, v12
	xor-long v223, v2, v34
	ushr-long v72, v57, v189
	ushr-int/2addr v10, v5
	xor-int/lit8 v176, v138, -118
	or-long v135, v242, v161
	rem-float v255, v235, v45
	xor-long v195, v59, v253
	float-to-int v1, v7
	double-to-float v5, v12
	or-int/lit8 v10, v10, 101
	div-int v63, v150, v10
	sub-float v196, v7, v91
	double-to-long v6, v12
	xor-int v134, v22, v84
	const-wide v34, 131072L
	or-long v2, v2, v34
	div-long/2addr v6, v2
	int-to-double v7, v14
	div-float/2addr v5, v9
	shl-int/2addr v4, v1
	sub-long v31, v2, v27
	rsub-int/lit8 v183, v92, 114
	div-float v138, v215, v214
	ushr-int v130, v240, v97
	div-double/2addr v12, v7
	or-int/lit16 v14, v14, 22831
	shl-int/lit8 v5, v190, -54
	ushr-long v15, v27, v118
	or-int/lit16 v6, v1, 688
	ushr-int/2addr v1, v10
	add-float v59, v248, v172
	mul-int/lit8 v56, v247, 111
	rem-double v17, v82, v12
	int-to-double v12, v4
	ushr-int v21, v247, v221
	mul-long v243, v31, v174
	neg-float v11, v9
	add-double v27, v79, v216
	neg-float v4, v9
	shr-int v86, v176, v143
	sub-float v235, v59, v45
	add-float/2addr v11, v9
	mul-int/lit16 v2, v14, -20522
	neg-long v8, v15
	shr-int/2addr v5, v2
	xor-long/2addr v15, v8
	and-long/2addr v8, v15
	or-int/lit8 v5, v5, 54
	div-int/2addr v1, v5
	float-to-int v13, v11
	add-long v29, v174, v228
	rem-int/lit8 v132, v10, 96
	and-int/lit16 v3, v13, 27306
	int-to-double v0, v10
	div-int/lit8 v188, v14, 27
	sub-int v16, v239, v26
	mul-int/lit8 v229, v151, 74
	move-wide/from16 v9, v107
	mul-double/2addr v9, v0
	ushr-int/lit8 v95, v132, 84
	move-wide/from16 v6, v243
	long-to-double v2, v6
	and-long v199, v34, v72
	or-int/lit8 v5, v5, 12
	div-int/2addr v13, v5
	mul-double v36, v216, v82
	rem-int/lit8 v14, v106, 28
	rsub-int/lit8 v177, v13, 45
	sub-float v47, v131, v76
	shr-long v228, v89, v133
	or-int/lit8 v13, v13, 122
	div-int/2addr v14, v13
	const-wide v228, 8L
	or-long v135, v135, v228
	rem-long v99, v6, v135
	move-wide/from16 v10, v34
	sub-long/2addr v10, v6
	long-to-int v2, v10
	or-int/lit8 v154, v154, 28
	rem-int v26, v48, v154
	rsub-int/lit8 v43, v247, -50
	shl-int v64, v177, v240
	or-long v254, v231, v174
	shr-int/2addr v5, v2
	shr-int/2addr v14, v13
	div-float v245, v138, v112
	shr-long v108, v223, v117
	double-to-int v3, v0
	shr-int v141, v148, v141
	double-to-float v9, v0
	mul-long v55, v218, v223
	const-wide v12, 0x276080dfda527e67L
	div-double/2addr v12, v0
	shl-long v125, v69, v67
	div-float/2addr v9, v4
	ushr-int/lit8 v181, v127, 87
	rsub-int/lit8 v86, v43, 121
	ushr-int/2addr v5, v14
	sub-float v57, v76, v19
	sub-long/2addr v6, v10
	add-double v234, v201, v170
	sub-double v114, v12, v82
	add-float/2addr v4, v9
	sub-float/2addr v4, v9
	float-to-int v12, v4
	not-long v14, v6
	div-int/lit8 v26, v63, -92
	int-to-long v15, v5
	shr-long/2addr v6, v5
	rem-double v18, v170, v36
	const-wide v29, 16L
	or-long v10, v10, v29
	div-long/2addr v6, v10
	or-long v82, v69, v199
	or-int/lit16 v3, v3, 9947
	shl-int/2addr v5, v3
	ushr-long/2addr v15, v5
	const-wide v0, 0xca7419e38396ab19L
	const-wide v10, 0x2f4bdfd1b42d75feL
	add-double/2addr v10, v0
	add-double/2addr v0, v10
	float-to-long v13, v9
	add-double v207, v170, v79
	sub-double/2addr v10, v0
	not-int v4, v12
	rsub-int v0, v3, 24935
	shr-long/2addr v6, v5
	double-to-float v4, v10
	shl-int/2addr v12, v2
	or-long/2addr v15, v13
	neg-int v8, v3
	const-wide v29, 4L
	or-long v89, v89, v29
	div-long v171, v99, v89
	mul-int/lit16 v0, v0, -15219
	int-to-short v3, v0
	xor-int/lit16 v3, v5, -3114
	int-to-char v6, v5
	or-int/2addr v0, v5
	and-long v111, v218, v69
	mul-float/2addr v4, v9
	const-wide v13, 0xd4fa66bfe3f49448L
	mul-double/2addr v13, v10
	rem-int/lit16 v0, v12, 24021
	mul-int/lit16 v6, v8, 20467
	shr-long v38, v34, v204
	ushr-int/2addr v2, v12
	add-float v135, v241, v78
	shr-long/2addr v15, v2
	shl-long/2addr v15, v5
	mul-double/2addr v10, v13
	or-int/lit8 v6, v6, 28
	rem-int/2addr v3, v6
	rem-double/2addr v10, v13
	mul-double/2addr v10, v13
	neg-double v1, v13
	double-to-int v15, v13
	rem-double/2addr v10, v1
	int-to-byte v8, v5
	float-to-int v3, v9
	neg-double v2, v1
	move-wide/from16 v10, v212
	move-wide/from16 v13, v254
	or-long/2addr v10, v13
	sub-float v34, v214, v135
	long-to-float v9, v13
	move-wide/from16 v8, v18
	rem-double/2addr v8, v2
	neg-int v4, v6
	add-int v111, v86, v247
	div-int/lit16 v2, v4, -7574
	or-int/lit8 v156, v156, 65
	rem-int v120, v84, v156
	or-int/2addr v4, v5
	xor-int/lit16 v12, v4, 2408
	int-to-long v7, v15
	shr-int/lit8 v111, v169, -45
	const v9, 0xa5bbf2ac
	move/from16 v7, v182
	add-float/2addr v7, v9
	ushr-int v217, v113, v120
	sub-int v146, v179, v106
	or-int/lit8 v64, v64, 89
	rem-int v215, v247, v64
	add-float v108, v7, v196
	xor-long v94, v161, v55
	and-int/2addr v0, v2
	shl-int/lit8 v156, v87, -64
	shl-int v26, v5, v101
	add-long v228, v89, v243
	and-int/2addr v6, v12
	sub-float v171, v45, v108
	sub-long/2addr v13, v10
	not-long v2, v13
	or-int/lit8 v0, v0, 12
	rem-int/2addr v6, v0
	sub-long v178, v89, v72
	int-to-double v1, v0
	float-to-double v3, v7
	long-to-float v7, v10
	add-int/lit16 v15, v0, 827
	double-to-long v0, v3
	add-long v30, v223, v55
	int-to-double v10, v6
	and-int v181, v154, v53
	ushr-int/lit8 v229, v191, -80
	rsub-int v2, v6, 15659
	and-long/2addr v0, v13
	ushr-long v230, v99, v81
	or-int/2addr v2, v12
	rem-int/lit8 v243, v204, 26
	long-to-int v14, v0
	or-int/lit8 v14, v14, 43
	div-int/2addr v15, v14
	rem-float v21, v185, v9
	add-double/2addr v3, v10
	or-long v58, v174, v69
	shr-long/2addr v0, v2
	neg-int v14, v6
	not-long v10, v0
	or-long v129, v55, v0
	add-int/2addr v15, v6
	rsub-int v6, v2, 32613
	long-to-double v7, v10
	rem-int/lit16 v14, v2, -11986
	rem-int/lit16 v2, v15, 15430
	add-int/2addr v14, v15
	xor-long/2addr v0, v10
	ushr-int v94, v155, v63
	shl-int/lit8 v171, v5, 92
	float-to-double v6, v9
	div-double v79, v234, v6
	int-to-char v4, v14
	or-int/lit16 v14, v2, 955
	move/from16 v15, v76
	sub-float/2addr v15, v9
	ushr-int/lit8 v37, v64, -48
	or-int/lit16 v11, v14, -25880
	sub-int/2addr v14, v2
	shl-int/lit8 v104, v147, -93
	shr-int/2addr v4, v12
	double-to-float v12, v6
	not-int v5, v2
	shl-long/2addr v0, v4
	move-wide/from16 v9, v207
	add-double/2addr v6, v9
	shl-int/lit8 v106, v67, -11
	sub-float/2addr v15, v12
	rem-float/2addr v12, v15
	ushr-int/lit8 v154, v2, 111
	shl-long v14, v254, v209
	div-double v215, v9, v79
	add-float v61, v108, v47
	mul-double/2addr v6, v9
	and-long/2addr v0, v14
	float-to-double v4, v12
	const-wide v0, 128L
	or-long v14, v14, v0
	div-long/2addr v0, v14
	or-int/lit8 v2, v2, 41
	rem-int/2addr v11, v2
	int-to-byte v11, v2
	long-to-int v15, v14
	mul-int/lit8 v57, v139, 75
	ushr-int/lit8 v198, v203, -112
	sub-float v149, v76, v34
	div-double/2addr v6, v4
	rsub-int/lit8 v223, v86, -80
	neg-float v15, v12
	or-int/lit8 v188, v188, 55
	rem-int v173, v67, v188
	move-wide/from16 v0, v55
	move-wide/from16 v14, v58
	and-long/2addr v0, v14
	sub-long/2addr v14, v0
	mul-double v83, v215, v237
	rsub-int/lit8 v233, v118, -61
	add-int/lit8 v193, v103, 37
	add-long v121, v0, v69
	xor-long/2addr v14, v0
	and-long v25, v14, v199
	double-to-int v11, v4
	float-to-int v3, v12
	and-long v226, v218, v89
	and-long/2addr v14, v0
	xor-int/2addr v11, v2
	ushr-long/2addr v0, v2
	int-to-short v0, v11
	or-int/lit8 v11, v11, 34
	rem-int/2addr v3, v11
	long-to-double v6, v14
	mul-long v191, v55, v174
	int-to-double v10, v3
	const v1, 0x247700b6
	rem-float/2addr v1, v12
	rem-int/lit8 v30, v86, 73
	neg-float v4, v1
	xor-int/lit8 v194, v147, -55
	rem-float/2addr v4, v12
	sub-int v195, v204, v111
	not-int v14, v2
	and-int/lit16 v13, v0, -28942
	int-to-double v4, v13
	ushr-int/lit8 v231, v85, -5
	int-to-short v8, v13
	not-int v3, v3
	shl-int v214, v128, v197
	int-to-char v1, v8
	and-int/2addr v14, v2
	xor-int/2addr v2, v1
	const v14, 0xd02ee9fa
	add-float/2addr v14, v12
	neg-int v4, v8
	neg-float v13, v12
	move-wide/from16 v1, v191
	move-wide/from16 v10, v263
	xor-long/2addr v1, v10
	and-int/2addr v3, v4
	or-int/lit8 v213, v190, -59
	and-int/lit8 v199, v223, 25
	or-long/2addr v10, v1
	div-int/lit8 v65, v197, 118
	add-int/2addr v0, v3
	float-to-long v10, v12
	const-wide v25, 16L
	or-long v10, v10, v25
	div-long/2addr v1, v10
	add-float/2addr v12, v13
	rem-int/lit8 v102, v22, -45
	neg-int v4, v4
	or-int v207, v252, v4
	move-wide/from16 v15, v215
	sub-double/2addr v6, v15
	const-wide v51, 262144L
	or-long v1, v1, v51
	div-long/2addr v10, v1
	sub-float/2addr v13, v12
	mul-double/2addr v15, v6
	or-int/lit8 v111, v142, -17
	neg-float v4, v13
	or-int/lit8 v94, v48, -82
	xor-int/lit16 v0, v3, 28006
	rsub-int v5, v3, -3798
	int-to-float v12, v0
	and-int/lit16 v7, v5, -21698
	add-float/2addr v12, v14
	xor-int/2addr v8, v0
	long-to-double v15, v1
	const-wide v10, 8192L
	or-long v161, v161, v10
	rem-long v80, v121, v161
	float-to-int v0, v14
	long-to-float v3, v10
	sub-int v127, v198, v30
	add-float v119, v47, v211
	float-to-double v5, v13
	ushr-int/lit8 v69, v132, 4
	mul-long/2addr v10, v1
	and-int/lit16 v3, v7, -27732
	or-int/lit16 v7, v8, -10049
	add-int/2addr v8, v7
	shr-int v98, v8, v195
	neg-long v4, v10
	or-int/lit8 v132, v132, 111
	rem-int v152, v120, v132
	rsub-int/lit8 v83, v98, 79
	ushr-long/2addr v10, v0
	sub-int/2addr v3, v0
	or-long v69, v129, v89
	mul-double v17, v27, v201
	const-wide v58, 65536L
	or-long v99, v99, v58
	rem-long v64, v58, v99
	neg-float v4, v12
	float-to-long v13, v13
	add-double v38, v17, v15
	and-long v30, v55, v13
	shl-int/lit8 v95, v153, 60
	int-to-float v3, v7
	ushr-long/2addr v1, v0
	double-to-int v12, v15
	shr-long/2addr v1, v0
	mul-double v14, v27, v215
	and-int v245, v213, v111
	mul-long/2addr v10, v1
	move-wide/from16 v6, v237
	add-double/2addr v14, v6
	shr-long v225, v129, v67
	mul-long v230, v69, v25
	and-int/lit8 v1, v207, -44
	div-float/2addr v4, v3
	neg-long v2, v10
	mul-int/lit16 v15, v1, 10727
	xor-long/2addr v2, v10
	const-wide v72, 1048576L
	or-long v2, v2, v72
	rem-long/2addr v10, v2
	shl-int/lit8 v116, v158, 63
	neg-int v6, v15
	move/from16 v0, v34
	rem-float/2addr v0, v4
	mul-long v30, v10, v2
	div-int/lit16 v15, v12, 6341
	move-wide/from16 v8, v271
	double-to-float v6, v8
	add-int v242, v1, v181
	ushr-long/2addr v2, v15
	sub-float v81, v182, v45
	shl-int/lit8 v26, v173, -95
	const-wide v178, 512L
	or-long v30, v30, v178
	div-long v254, v2, v30
	and-int/lit8 v105, v20, -108
	div-int/lit8 v203, v195, 70
	int-to-short v6, v12
	and-int/lit16 v9, v1, -1251
	int-to-long v11, v6
	xor-int/lit16 v6, v1, -5729
	and-long v8, v225, v99
	mul-double v59, v17, v201
	const-wide v125, 16L
	or-long v254, v254, v125
	rem-long v203, v99, v254
	const-wide v161, 2L
	or-long v129, v129, v161
	div-long v28, v230, v129
	rem-int/lit16 v6, v6, 9365
	rem-int/lit16 v2, v6, -21126
	float-to-long v15, v0
	rem-float v45, v211, v185
	and-int/2addr v6, v1
	and-long v140, v51, v89
	shl-long v76, v161, v53
	or-int v187, v197, v155
	long-to-double v1, v15
	or-int/lit16 v6, v6, 12482
	long-to-int v1, v11
	div-float/2addr v4, v0
	ushr-long/2addr v8, v1
	rem-int/lit16 v3, v1, 30951
	shr-int v179, v195, v171
	div-float/2addr v0, v4
	or-int/2addr v3, v6
	add-int/lit8 v103, v155, 5
	const-wide v129, 262144L
	or-long v8, v8, v129
	rem-long/2addr v11, v8
	or-int/2addr v3, v1
	div-float/2addr v0, v4
	add-float v201, v4, v78
	shr-int v11, v20, v98
	add-double v225, v17, v114
	not-long v15, v8
	rem-int/lit16 v11, v6, 24386
	move-wide/from16 v13, v237
	const-wide v2, 0x4a23b0f23cd7292bL
	mul-double/2addr v2, v13
	int-to-byte v1, v11
	const-wide v55, 32L
	or-long v203, v203, v55
	div-long v222, v191, v203
	shl-int v22, v128, v134
	rem-int/lit8 v77, v101, -3
	ushr-int/lit8 v211, v156, 62
	rem-int/lit8 v66, v207, -26
	double-to-float v4, v13
	const-wide v51, 256L
	or-long v125, v125, v51
	rem-long v105, v218, v125
	double-to-float v3, v2
	move-wide/from16 v3, v225
	rem-double/2addr v3, v13
	sub-int/2addr v1, v6
	and-long v211, v203, v161
	shl-long/2addr v15, v1
	int-to-char v3, v6
	long-to-double v14, v8
	double-to-int v8, v14
	const-wide v2, 0x957de74f608016f5L
	not-long v8, v2
	ushr-int/2addr v11, v1
	double-to-long v3, v14
	const-wide v8, 1073741824L
	or-long v64, v64, v8
	rem-long v224, v121, v64
	float-to-long v6, v0
	neg-double v3, v14
	div-double v65, v14, v3
	neg-int v4, v11
	xor-long v125, v230, v222
	float-to-long v13, v0
	div-int/lit16 v9, v11, -26779
	sub-int/2addr v11, v1
	shl-int/2addr v9, v1
	not-int v4, v4
	ushr-int/lit8 v90, v111, 74
	move-wide/from16 v4, v59
	move-wide/from16 v11, v17
	rem-double/2addr v11, v4
	shl-long/2addr v13, v1
	add-int/lit16 v14, v9, -15358
	sub-int/2addr v1, v14
	add-float v38, v135, v131
	or-int/lit8 v14, v14, 24
	rem-int/2addr v9, v14
	sub-float v40, v145, v138
	mul-float v136, v145, v166
	or-int/lit16 v8, v1, 7420
	xor-int/2addr v8, v1
	const-wide v10, 0xfaca7cf74a818350L
	sub-long/2addr v6, v10
	add-int/lit8 v229, v37, 5
	or-long/2addr v10, v6
	not-long v6, v6
	rsub-int v3, v14, 13933
	sub-int/2addr v8, v14
	or-long/2addr v6, v10
	neg-double v5, v4
	long-to-double v2, v10
	sub-int v120, v177, v132
	not-long v6, v10
	and-int v227, v229, v68
	long-to-int v12, v6
	shr-long v97, v10, v9
	and-long v149, v99, v129
	and-long v121, v129, v140
	long-to-int v11, v10
	const-wide v15, 0xe2b041f0c21054b8L
	add-long/2addr v6, v15
	sub-long v147, v254, v97
	rem-double v219, v114, v234
	and-long/2addr v6, v15
	ushr-long/2addr v6, v14
	move/from16 v5, v108
	mul-float/2addr v5, v0
	shr-int/lit8 v41, v117, -14
	sub-long v177, v125, v6
	add-int v76, v176, v117
	xor-long v128, v55, v125
	div-float/2addr v5, v0
	double-to-int v1, v2
	or-int/lit8 v90, v90, 35
	div-int v141, v187, v90
	ushr-long/2addr v6, v14
	mul-long/2addr v15, v6
	rem-float/2addr v0, v5
	and-long v125, v30, v149
	div-float v219, v136, v47
	mul-float/2addr v0, v5
	ushr-long v242, v125, v83
	const-wide v222, 65536L
	or-long v15, v15, v222
	rem-long/2addr v6, v15
	shr-long/2addr v6, v12
	shl-int/2addr v1, v9
	shl-long/2addr v15, v8
	or-int/2addr v11, v12
	add-int/2addr v11, v9
	int-to-byte v10, v9
	int-to-char v6, v9
	add-int/2addr v12, v11
	double-to-long v7, v2
	rem-int/lit16 v6, v14, 23684
	int-to-double v1, v14
	shr-int/2addr v12, v14
	int-to-double v7, v10
	shr-long v102, v242, v37
	or-int/lit8 v131, v48, -105
	const-wide v55, 524288L
	or-long v121, v121, v55
	div-long v165, v147, v121
	add-double v98, v59, v17
	or-int/lit16 v4, v6, 31179
	shr-long v24, v102, v101
	add-int/lit16 v1, v10, 8266
	and-long v231, v51, v222
	neg-float v4, v5
	ushr-int/lit8 v170, v142, 104
	rem-int/lit8 v36, v183, -118
	mul-float/2addr v4, v0
	sub-float/2addr v0, v5
	xor-int v166, v190, v153
	or-int v18, v62, v152
	rem-int/lit8 v145, v252, 73
	add-long v158, v174, v161
	div-int/lit16 v11, v14, -17743
	or-int v204, v71, v117
	long-to-double v2, v15
	long-to-float v8, v15
	rsub-int/lit8 v164, v14, 23
	mul-double v85, v59, v215
	xor-int/lit16 v14, v14, -14971
	shl-int/lit8 v74, v63, -6
	or-int/lit8 v12, v12, 61
	div-int/2addr v1, v12
	and-int/2addr v11, v12
	rem-int/lit8 v94, v179, -80
	or-int/lit8 v90, v90, 24
	rem-int v138, v154, v90
	move-wide/from16 v0, v191
	xor-long/2addr v0, v15
	int-to-float v7, v14
	not-long v14, v0
	add-int/lit16 v0, v11, -17885
	not-int v6, v10
	shr-int/lit8 v110, v37, 123
	or-int/lit8 v71, v71, 48
	div-int v146, v213, v71
	or-int/lit16 v12, v6, 8052
	shr-int v234, v83, v12
	sub-float v232, v185, v21
	sub-int v165, v173, v227
	rsub-int/lit8 v65, v198, 116
	long-to-float v9, v14
	mul-long v118, v128, v69
	or-int/lit8 v187, v187, 40
	div-int v219, v205, v187
	xor-int/lit8 v250, v219, -106
	double-to-float v12, v2
	float-to-long v14, v12
	rem-float/2addr v4, v9
	mul-int/lit16 v15, v6, -19672
	const-wide v11, 0x271e51faeac20406L
	const-wide v2, 0xaaa591b33eddf135L
	mul-long/2addr v2, v11
	int-to-double v15, v15
	int-to-byte v7, v0
	or-int/lit16 v12, v7, -17695
	const-wide v69, 16777216L
	or-long v174, v174, v69
	div-long v48, v222, v174
	const-wide v0, 0x4545f4bcb697df4bL
	and-long/2addr v2, v0
	float-to-double v11, v8
	div-double v154, v15, v215
	mul-int/lit16 v12, v7, -29440
	float-to-long v5, v9
	xor-int v73, v68, v164
	const-wide v147, 256L
	or-long v5, v5, v147
	div-long/2addr v2, v5
	add-double v254, v85, v15
	and-long/2addr v5, v0
	shl-int/lit8 v116, v151, 49
	add-int/lit8 v143, v193, -59
	add-int/2addr v12, v10
	and-int/2addr v7, v10
	xor-long/2addr v2, v5
	rem-int/lit8 v45, v117, 38
	add-int/lit8 v167, v169, -14
	add-float/2addr v4, v9
	or-int/lit8 v7, v7, 100
	div-int/2addr v12, v7
	ushr-long v239, v242, v194
	shl-long v53, v191, v142
	or-int/lit8 v23, v187, -23
	xor-int/lit8 v180, v213, 68
	sub-float/2addr v9, v4
	or-int/lit8 v10, v10, 5
	rem-int/2addr v12, v10
	int-to-short v13, v7
	mul-float/2addr v9, v4
	shr-long/2addr v2, v7
	and-long/2addr v5, v2
	neg-float v3, v8
	or-int/lit8 v12, v12, 65
	rem-int/2addr v13, v12
	or-int/2addr v10, v7
	rem-int/lit16 v0, v7, -5234
	const-wide v121, 524288L
	or-long v105, v105, v121
	rem-long v70, v158, v105
	mul-double v157, v85, v98
	add-long v189, v147, v5
	const-wide v191, 524288L
	or-long v51, v51, v191
	rem-long v191, v177, v51
	move-wide/from16 v9, v189
	const-wide v102, 4096L
	or-long v5, v5, v102
	rem-long/2addr v9, v5
	add-int/lit16 v8, v7, 28919
	const-wide v28, 268435456L
	or-long v224, v224, v28
	div-long v153, v211, v224
	const-wide v224, 512L
	or-long v9, v9, v224
	rem-long/2addr v5, v9
	div-int/lit16 v13, v7, -27297
	add-long/2addr v9, v5
	div-int/lit16 v12, v7, 1600
	or-int/lit8 v207, v207, 13
	rem-int v243, v104, v207
	add-int v212, v65, v176
	xor-int v69, v74, v95
	shr-int/lit8 v84, v165, -71
	shr-long/2addr v9, v12
	double-to-int v5, v15
	neg-float v4, v3
	long-to-int v4, v9
	const-wide v9, 0xcc6d8c95eaba0b7cL
	move-wide/from16 v15, v70
	mul-long/2addr v9, v15
	long-to-double v0, v9
	sub-float v241, v249, v185
	and-int/lit8 v168, v68, 50
	int-to-float v2, v8
	move-wide/from16 v12, v271
	div-double/2addr v12, v0
	add-int/lit16 v8, v5, 1805
	xor-long/2addr v9, v15
	sub-long/2addr v9, v15
	sub-int v220, v166, v8
	xor-int/lit8 v209, v8, -2
	sub-long/2addr v9, v15
	sub-long v86, v174, v191
	or-long v91, v189, v86
	int-to-float v8, v5
	float-to-long v10, v2
	long-to-double v9, v15
	rsub-int v10, v4, 26982
	xor-int/lit8 v60, v68, -13
	and-int/lit8 v24, v131, 25
	const-wide v149, 8L
	or-long v118, v118, v149
	div-long v47, v28, v118
	add-int v26, v199, v60
	const-wide v13, 0x9d27d3210bf26dfaL
	mul-long/2addr v15, v13
	rem-int/lit8 v49, v84, -113
	rsub-int/lit8 v107, v195, 48
	and-int/2addr v10, v7
	sub-long/2addr v15, v13
	mul-int v163, v198, v220
	sub-float/2addr v3, v2
	or-int/lit8 v24, v24, 6
	rem-int v90, v77, v24
	move-wide/from16 v12, v254
	add-double/2addr v0, v12
	ushr-long v58, v30, v142
	and-long v39, v239, v55
	mul-int/lit8 v148, v145, 100
	const-wide v174, 33554432L
	or-long v86, v86, v174
	div-long v11, v239, v86
	div-double v146, v237, v254
	mul-int/lit16 v11, v7, 20803
	div-double v156, v114, v254
	ushr-long/2addr v15, v7
	and-int/lit8 v136, v23, -72
	rem-float v16, v8, v3
	rem-float v174, v8, v78
	xor-int/lit8 v221, v220, -9
	rsub-int v14, v10, -15709
	const-wide v6, 0x491505f3464cbeddL
	neg-long v12, v6
	shr-int v101, v116, v217
	shr-int v117, v171, v168
	xor-int v153, v107, v207
	mul-long v124, v222, v70
	and-int/2addr v10, v5
	add-int/lit16 v10, v14, -29422
	float-to-double v1, v3
	long-to-int v1, v12
	and-long v243, v149, v191
	const-wide v4, 0x12a45a003321ac75L
	double-to-int v3, v4
	or-long/2addr v12, v6
	and-int v247, v69, v22
	int-to-short v2, v10
	int-to-char v7, v10
	sub-double v45, v98, v114
	or-int/lit8 v139, v139, 47
	rem-int v233, v117, v139
	or-int/lit8 v10, v10, 121
	div-int v40, v153, v10
	move-wide/from16 v3, v177
	and-long/2addr v3, v12
	add-int/2addr v2, v11
	mul-int v207, v164, v24
	add-float v83, v78, v185
	rsub-int v13, v11, -28591
	ushr-int v230, v193, v11
	or-int/lit8 v139, v139, 47
	div-int v241, v207, v139
	xor-int/lit16 v10, v11, -28513
	int-to-long v4, v13
	rem-double v63, v45, v114
	or-int/lit8 v7, v7, 79
	div-int/2addr v13, v7
	mul-double v60, v237, v156
	move-wide/from16 v15, v156
	move-wide/from16 v6, v156
	sub-double/2addr v15, v6
	float-to-double v1, v8
	rem-int/lit8 v77, v207, -63
	or-int v215, v94, v113
	or-long v57, v177, v91
	sub-double/2addr v1, v15
	and-int v55, v171, v73
	float-to-long v10, v8
	or-int/lit8 v75, v55, 85
	sub-double/2addr v1, v15
	mul-int/lit16 v12, v13, -5923
	const-wide v30, 1024L
	or-long v4, v4, v30
	rem-long/2addr v10, v4
	mul-long v159, v28, v191
	shr-long/2addr v10, v12
	sub-int v97, v241, v198
	and-long/2addr v4, v10
	not-int v14, v13
	xor-int/lit8 v28, v26, -109
	ushr-long v224, v224, v168
	xor-int/lit16 v14, v14, -24057
	const-wide v159, 262144L
	or-long v177, v177, v159
	rem-long v224, v128, v177
	mul-double/2addr v15, v1
	add-long/2addr v4, v10
	move/from16 v15, v201
	rem-float/2addr v15, v8
	mul-double/2addr v6, v1
	shl-long/2addr v4, v13
	shr-int/lit8 v8, v176, 65
	neg-long v3, v4
	and-int/2addr v8, v13
	long-to-double v2, v10
	long-to-int v11, v10
	int-to-float v14, v14
	mul-int/lit8 v181, v131, -57
	add-long v68, v86, v102
	shr-long v52, v224, v221
	div-float v148, v83, v14
	or-long v122, v177, v52
	shr-long v216, v224, v113
	xor-int/lit16 v6, v13, 19652
	move-wide/from16 v3, v222
	move-wide/from16 v14, v263
	or-long/2addr v3, v14
	rem-double v210, v63, v45
	move-wide/from16 v10, v45
	neg-double v6, v10
	and-int/lit8 v116, v188, 124
	mul-double v214, v210, v98
	or-int/lit8 v104, v104, 102
	div-int v171, v144, v104
	add-int v58, v179, v166
	neg-int v9, v13
	sub-double/2addr v6, v10
	or-int/lit8 v13, v13, 8
	rem-int/2addr v12, v13
	int-to-byte v4, v12
	move/from16 v14, v83
	float-to-double v13, v14
	and-int/2addr v8, v12
	const-wide v0, 0x78779db6fc5fca8eL
	const-wide v12, 0x9c10764f816dbba8L
	or-long/2addr v12, v0
	sub-long/2addr v12, v0
	or-int/lit8 v137, v194, -15
	neg-long v13, v12
	or-int/lit8 v8, v8, 46
	rem-int/2addr v9, v8
	and-int/lit8 v8, v8, 24
	mul-int v96, v179, v77
	rem-double/2addr v10, v6
	and-long/2addr v13, v0
	double-to-int v3, v6
	mul-int/lit16 v15, v4, 22410
	shl-long/2addr v0, v3
	xor-int/lit16 v12, v15, -5056
	rem-double/2addr v6, v10
	shr-int/lit8 v136, v180, 117
	add-float v98, v182, v184
	shr-int v244, v49, v169
	sub-int/2addr v9, v8
	ushr-int/2addr v8, v9
	or-int/2addr v4, v15
	xor-long v236, v159, v86
	add-int/lit16 v3, v9, 22793
	move/from16 v0, v34
	neg-float v13, v0
	const-wide v86, 8L
	or-long v224, v224, v86
	rem-long v71, v149, v224
	move-wide/from16 v15, v122
	ushr-long/2addr v15, v12
	sub-double/2addr v6, v10
	or-int/2addr v8, v12
	double-to-int v1, v10
	or-int/lit8 v1, v1, 91
	rem-int/2addr v3, v1
	mul-double v233, v114, v10
	sub-double v90, v45, v146
	add-int/lit8 v255, v18, -18
	mul-long v111, v128, v224
	const-wide v222, 131072L
	or-long v124, v124, v222
	div-long v146, v68, v124
	sub-int v145, v95, v9
	or-int v166, v151, v227
	add-int/2addr v12, v9
	div-float/2addr v13, v0
	int-to-char v11, v9
	and-int/lit16 v0, v11, 25479
	float-to-double v15, v13
	and-int/2addr v8, v11
	float-to-long v14, v13
	move-wide/from16 v2, v236
	add-long/2addr v2, v14
	and-int/2addr v11, v8
	xor-int v119, v170, v247
	mul-int/2addr v8, v12
	shl-long/2addr v14, v0
	move/from16 v10, v185
	add-float/2addr v13, v10
	float-to-long v11, v10
	and-int/lit8 v249, v168, 85
	ushr-long v26, v161, v151
	or-int/lit8 v151, v151, 59
	div-int v84, v169, v151
	double-to-long v14, v6
	or-int v170, v120, v167
	or-int/lit8 v4, v4, 62
	div-int/2addr v9, v4
	or-long v246, v30, v102
	shr-int/lit8 v86, v193, 81
	rem-float v151, v81, v185
	add-long/2addr v11, v2
	shr-int/lit8 v69, v49, -29
	add-double v6, v45, v210
	move-wide/from16 v2, v114
	sub-double/2addr v6, v2
	and-int v208, v18, v110
	neg-float v0, v13
	sub-double/2addr v6, v2
	const-wide v47, 524288L
	or-long v105, v105, v47
	rem-long v239, v102, v105
	add-double/2addr v6, v2
	not-long v13, v14
	mul-double v46, v2, v214
	int-to-char v1, v1
	not-int v3, v8
	float-to-double v15, v10
	xor-int/2addr v9, v1
	long-to-float v7, v11
	sub-long/2addr v11, v13
	int-to-long v14, v9
	add-long v180, v236, v146
	const-wide v2, 0x2f875f456e409696L
	move-wide/from16 v10, v63
	sub-double/2addr v2, v10
	div-int/lit8 v229, v69, 12
	const-wide v2, 0xac164a61d3ee336fL
	and-long/2addr v2, v14
	div-float/2addr v0, v7
	add-int/lit16 v15, v4, -2327
	double-to-int v6, v10
	shr-long v210, v124, v77
	sub-float/2addr v0, v7
	float-to-int v9, v7
	const-wide v12, 0x70324b6b68bbf91aL
	and-long/2addr v12, v2
	xor-int/lit8 v46, v137, 102
	and-int/2addr v1, v9
	sub-double v185, v63, v10
	int-to-char v5, v6
	ushr-long v203, v239, v199
	sub-float/2addr v0, v7
	div-float v95, v78, v83
	const-wide v161, 67108864L
	or-long v2, v2, v161
	div-long/2addr v12, v2
	ushr-long/2addr v2, v9
	shr-long v47, v210, v110
	neg-float v6, v7
	float-to-long v6, v7
	float-to-int v3, v0
	move/from16 v15, v0
	sub-float/2addr v15, v0
	long-to-int v10, v6
	ushr-int/2addr v9, v8
	mul-int/2addr v8, v5
	mul-float v72, v248, v83
	or-long/2addr v6, v12
	const-wide v26, 1073741824L
	or-long v236, v236, v26
	rem-long v242, v102, v236
	add-int/lit16 v11, v1, 29157
	move-wide/from16 v9, v269
	double-to-float v3, v9
	neg-double v2, v9
	and-int v10, v250, v18
	rem-int/lit16 v2, v1, 14765
	or-long/2addr v6, v12
	move-wide/from16 v10, v63
	move-wide/from16 v1, v273
	sub-double/2addr v1, v10
	double-to-float v13, v10
	and-long v227, v149, v222
	move-wide/from16 v4, v159
	mul-long/2addr v6, v4
	shr-long v153, v180, v76
	div-double v82, v63, v1
	and-int/lit8 v176, v18, -44
	or-int/lit16 v15, v8, 28453
	mul-int/lit16 v15, v8, 13660
	rsub-int v13, v8, -5906
	or-long v168, v124, v222
	xor-int v2, v199, v23
	add-int v250, v134, v97
	xor-int/2addr v8, v13
	sub-double v244, v185, v63
	ushr-int/lit8 v211, v113, 20
	sub-long v44, v128, v203
	double-to-float v9, v10
	long-to-float v14, v6
	move-wide/from16 v1, v10
	sub-double/2addr v1, v10
	and-int/lit8 v242, v165, -65
	shr-long/2addr v6, v13
	add-float/2addr v0, v9
	sub-long v28, v180, v246
	and-long/2addr v4, v6
	mul-float/2addr v0, v14
	shr-long/2addr v4, v15
	double-to-long v15, v1
	div-int/lit16 v4, v8, 7569
	mul-int v184, v22, v107
	const-wide v15, 8L
	or-long v6, v6, v15
	rem-long v239, v146, v6
	double-to-int v11, v10
	xor-int/2addr v8, v11
	sub-float/2addr v9, v14
	xor-int/2addr v4, v11
	neg-float v4, v9
	neg-float v10, v9
	mul-int v176, v65, v134
	ushr-int/2addr v11, v8
	int-to-float v12, v11
	sub-int/2addr v13, v11
	add-float v166, v12, v108
	double-to-long v9, v1
	sub-int v212, v242, v208
	rsub-int/lit8 v25, v179, 123
	add-float/2addr v14, v4
	add-long v197, v105, v236
	div-double v179, v114, v244
	ushr-int/lit8 v191, v205, -128
	int-to-float v8, v11
	int-to-short v9, v11
	and-int/lit8 v108, v187, 103
	shr-int/lit8 v88, v127, 42
	rem-int/lit8 v199, v212, 81
	or-int/lit8 v221, v144, 11
	mul-int/lit8 v168, v22, 20
	xor-long v47, v189, v216
	rem-int/lit8 v101, v133, -54
	float-to-long v9, v12
	const-wide v227, 8388608L
	or-long v9, v9, v227
	div-long/2addr v15, v9
	xor-int v228, v65, v116
	sub-float v202, v34, v81
	mul-float/2addr v0, v12
	float-to-double v7, v14
	float-to-long v0, v14
	shr-long v48, v0, v163
	rsub-int/lit8 v209, v94, 20
	double-to-float v8, v7
	const-wide v28, 1048576L
	or-long v28, v28, v28
	rem-long v204, v30, v28
	mul-float v218, v95, v34
	add-int/lit8 v222, v219, -61
	and-long v195, v236, v111
	float-to-double v2, v8
	mul-int/lit8 v91, v142, 107
	sub-float/2addr v14, v8
	div-int/lit8 v3, v25, -92
	sub-int/2addr v13, v11
	mul-int v141, v131, v18
	mul-long v223, v44, v28
	and-long/2addr v15, v0
	sub-int v153, v18, v144
	move-wide/from16 v2, v273
	const-wide v1, 0xe4437191ebfa5feL
	const-wide v8, 0x4179fe9cf5ab0542L
	mul-double/2addr v1, v8
	int-to-char v15, v13
	sub-float v108, v135, v182
	const-wide v10, 0x51a08482acaf8fbdL
	move-wide/from16 v3, v149
	and-long/2addr v10, v3
	add-int v8, v144, v184
	xor-int/2addr v15, v8
	or-long/2addr v10, v3
	int-to-long v6, v13
	or-int v208, v117, v142
	add-float/2addr v12, v14
	const-wide v10, 4096L
	or-long v105, v105, v10
	rem-long v118, v111, v105
	move-wide/from16 v12, v233
	mul-double/2addr v1, v12
	mul-double v174, v82, v12
	and-int/lit16 v13, v8, 8857
	add-int/lit8 v240, v145, 46
	xor-int/lit16 v5, v15, -23935
	shr-int/lit8 v120, v136, 65
	move/from16 v2, v148
	div-float/2addr v14, v2
	move-wide/from16 v6, v271
	move-wide/from16 v10, v233
	rem-double/2addr v6, v10
	double-to-int v6, v10
	or-int/lit8 v6, v6, 124
	div-int/2addr v13, v6
	or-int/2addr v5, v13
	or-int/lit8 v15, v15, 115
	div-int/2addr v13, v15
	move-wide/from16 v10, v60
	move-wide/from16 v2, v269
	div-double/2addr v2, v10
	xor-int/lit8 v161, v165, -108
	xor-int v148, v13, v58
	mul-int v218, v131, v230
	sub-int v98, v13, v191
	shr-int v73, v163, v249
	move-wide/from16 v5, v236
	shr-long/2addr v5, v15
	rem-double/2addr v10, v2
	add-int/2addr v8, v13
	rsub-int/lit8 v198, v104, 85
	ushr-int/lit8 v107, v230, 25
	const-wide v159, 32768L
	or-long v236, v236, v159
	rem-long v12, v30, v236
	or-int/lit8 v201, v212, -11
	int-to-char v8, v8
	or-int/lit8 v94, v69, 122
	shl-int v194, v221, v165
	shr-int/lit8 v231, v164, -44
	or-int/2addr v15, v8
	ushr-int/lit8 v148, v20, -62
	mul-int v20, v170, v242
	and-int/lit8 v250, v165, 24
	mul-int/2addr v15, v8
	const-wide v128, 67108864L
	or-long v236, v236, v128
	rem-long v59, v48, v236
	ushr-int/2addr v15, v8
	xor-long/2addr v12, v5
	sub-long/2addr v12, v5
	neg-float v8, v14
	add-long v177, v105, v102
	rem-double/2addr v10, v2
	ushr-long v186, v111, v168
	move/from16 v4, v96
	mul-int/2addr v4, v15
	xor-int v187, v15, v117
	xor-int v88, v173, v77
	add-int/lit16 v12, v4, -6331
	div-int/lit16 v3, v15, 17369
	sub-int/2addr v15, v3
	double-to-int v1, v10
	div-float/2addr v14, v8
	xor-int/lit16 v6, v3, -23609
	int-to-char v3, v4
	ushr-int/2addr v1, v15
	ushr-int/lit8 v36, v120, -84
	and-long v200, v102, v44
	move-wide/from16 v5, v271
	add-double/2addr v10, v5
	shr-int/lit8 v194, v222, 11
	xor-int v99, v25, v187
	xor-int/2addr v1, v4
	add-long v173, v204, v236
	move-wide/from16 v8, v159
	long-to-int v1, v8
	shr-int v65, v212, v23
	add-long v31, v177, v149
	shl-long/2addr v8, v1
	rem-float v42, v151, v34
	move/from16 v15, v202
	rem-float/2addr v15, v14
	int-to-long v5, v3
	add-long/2addr v8, v5
	div-int/lit8 v45, v84, -15
	mul-float/2addr v15, v14
	xor-int/lit8 v145, v120, 19
	ushr-int v95, v163, v213
	float-to-long v14, v14
	neg-long v1, v5
	shr-long/2addr v1, v12
	or-int/lit8 v4, v4, 63
	rem-int/2addr v12, v4
	mul-int v1, v75, v107
	xor-long v203, v177, v223
	shl-int/lit8 v44, v212, 59
	double-to-float v13, v10
	mul-long v225, v102, v177
	div-double v6, v214, v63
	move/from16 v15, v182
	mul-float/2addr v15, v13
	add-int/lit16 v14, v12, -14913
	or-int/lit8 v208, v208, 32
	div-int v152, v143, v208
	rsub-int/lit8 v215, v207, 77
	double-to-float v15, v10
	rem-float v103, v42, v108
	shl-int/lit8 v224, v101, -40
	or-int/lit8 v14, v14, 105
	div-int/2addr v1, v14
	shl-int/lit8 v219, v184, -9
	shl-int/lit8 v84, v36, -59
	rsub-int v11, v3, 11277
	const-wide v15, 0xf335b0f147731c34L
	xor-long/2addr v8, v15
	float-to-int v4, v13
	move/from16 v14, v78
	sub-float/2addr v13, v14
	shr-long v63, v200, v219
	shl-int/lit8 v81, v241, 35
	div-int/lit8 v187, v164, 18
	and-int/lit8 v177, v94, -47
	shr-int v78, v194, v131
	add-float/2addr v14, v13
	mul-int v243, v95, v45
	int-to-double v14, v11
	shr-int/lit8 v228, v137, -93
	mul-long v48, v189, v105
	or-int/lit8 v12, v12, 20
	div-int v67, v215, v12
	rem-double/2addr v6, v14
	sub-double/2addr v14, v6
	shr-int/2addr v1, v11
	shr-long v103, v146, v242
	xor-int/lit8 v86, v142, 118
	int-to-double v14, v4
	double-to-float v5, v14
	int-to-float v0, v1
	long-to-float v2, v8
	move-wide/from16 v13, v59
	and-long/2addr v13, v8
	or-int/lit8 v11, v11, 81
	div-int v157, v215, v11
	ushr-long v204, v59, v199
	rsub-int v2, v12, 7267
	shr-long v51, v195, v170
	long-to-double v12, v8
	shr-long v223, v103, v18
	add-int v30, v222, v208
	mul-int/lit16 v5, v11, 29272
	shr-int/2addr v5, v3
	div-double v181, v6, v179
	mul-double/2addr v6, v12
	mul-float v239, v42, v248
	long-to-float v13, v8
	shl-int/2addr v4, v3
	div-double v8, v181, v82
	move-wide/from16 v12, v111
	ushr-long/2addr v12, v3
	move-wide/from16 v9, v195
	and-long/2addr v12, v9
	const-wide v236, 65536L
	or-long v146, v146, v236
	rem-long v16, v103, v146
	or-int/2addr v3, v11
	or-int/lit8 v11, v11, 93
	div-int/2addr v2, v11
	mul-int/lit16 v4, v11, 17870
	const-wide v12, 262144L
	or-long v149, v149, v12
	rem-long v230, v223, v149
	const-wide v63, 131072L
	or-long v12, v12, v63
	div-long/2addr v9, v12
	or-int/lit8 v2, v2, 82
	div-int/2addr v4, v2
	long-to-float v11, v12
	double-to-long v1, v6
	xor-int v249, v131, v98
	move-wide/from16 v9, v179
	div-double/2addr v6, v9
	double-to-float v3, v9
	and-long v99, v195, v216
	shl-long/2addr v1, v4
	const-wide v128, 32768L
	or-long v195, v195, v128
	rem-long v32, v51, v195
	div-float/2addr v0, v3
	int-to-long v14, v4
	rem-float v120, v38, v202
	double-to-float v3, v9
	int-to-float v15, v4
	const-wide v32, 134217728L
	or-long v225, v225, v32
	rem-long v76, v32, v225
	double-to-int v7, v9
	or-int/2addr v4, v7
	mul-int/lit16 v7, v4, 9577
	const-wide v111, 1024L
	or-long v12, v12, v111
	rem-long/2addr v1, v12
	mul-int v155, v207, v213
	shr-long v144, v189, v107
	sub-long v165, v223, v173
	add-int v196, v113, v222
	long-to-double v6, v12
	ushr-int v198, v81, v250
	or-int v4, v117, v196
	add-int/lit8 v198, v255, -54
	and-int/lit8 v25, v37, -7
	shl-int/lit8 v108, v44, -93
	float-to-int v5, v11
	mul-int/lit8 v125, v143, 59
	mul-float v35, v34, v239
	mul-long/2addr v12, v1
	rem-int/lit8 v214, v193, -6
	rem-double/2addr v9, v6
	neg-float v0, v3
	const-wide v189, 8388608L
	or-long v1, v1, v189
	div-long/2addr v12, v1
	and-int v211, v75, v110
	shl-long v15, v128, v155
	sub-int/2addr v4, v5
	not-int v6, v5
	xor-int/2addr v4, v5
	const-wide v105, 4L
	or-long v15, v15, v105
	rem-long/2addr v1, v15
	shr-long v212, v159, v133
	long-to-double v11, v12
	ushr-int v70, v46, v58
	ushr-int v23, v131, v215
	mul-int v108, v43, v96
	rsub-int v0, v5, 2998
	move/from16 v1, v260
	sub-float/2addr v1, v3
	ushr-long v88, v204, v113
	shr-long/2addr v15, v5
	ushr-int/lit8 v119, v188, -127
	move-wide/from16 v3, v76
	const-wide v146, 524288L
	or-long v15, v15, v146
	rem-long/2addr v3, v15
	sub-float v129, v72, v38
	sub-float v114, v34, v1
	int-to-char v15, v5
	add-double v119, v82, v179
	double-to-long v9, v11
	const-wide v76, 1024L
	or-long v9, v9, v76
	div-long/2addr v3, v9
	xor-int v74, v155, v191
	long-to-float v15, v3
	or-int/2addr v0, v6
	add-int/lit8 v96, v219, 36
	xor-int/lit16 v6, v6, -7519
	rsub-int/lit8 v196, v133, 0
	xor-long/2addr v9, v3
	rem-double v17, v11, v181
	or-int v9, v40, v108
	rem-double v227, v179, v11
	or-int/lit8 v21, v91, -103
	shl-int/2addr v9, v6
	and-int/lit8 v19, v168, 104
	div-int/lit16 v15, v0, -20
	shr-long/2addr v3, v9
	long-to-int v14, v3
	sub-int/2addr v9, v15
	neg-float v13, v1
	int-to-char v14, v0
	div-float/2addr v13, v1
	sub-double v3, v82, v11
	or-int/lit8 v9, v9, 7
	div-int/2addr v0, v9
	const-wide v10, 0x130df54afbecf90dL
	ushr-long/2addr v10, v6
	add-float/2addr v1, v13
	or-int/lit8 v193, v193, 79
	rem-int v93, v167, v193
	shl-long/2addr v10, v15
	mul-float v151, v42, v151
	neg-long v7, v10
	long-to-double v12, v10
	or-int/lit8 v9, v9, 112
	rem-int/2addr v6, v9
	mul-long/2addr v7, v10
	neg-float v7, v1
	float-to-int v11, v7
	neg-float v10, v1
	const-wide v159, 16384L
	or-long v216, v216, v159
	rem-long v208, v111, v216
	ushr-int/lit8 v123, v243, -93
	shl-int/2addr v0, v9
	or-long v34, v144, v88
	shl-int v160, v55, v155
	sub-float v72, v232, v248
	add-double/2addr v3, v12
	sub-int/2addr v11, v15
	move-wide/from16 v1, v63
	move-wide/from16 v1, v48
	move-wide/from16 v2, v165
	move-wide/from16 v4, v263
	mul-long/2addr v4, v2
	mul-long v247, v111, v144
	ushr-int/2addr v15, v0
	or-long v120, v223, v204
	const-wide v34, 2048L
	or-long v200, v200, v34
	rem-long v220, v2, v200
	mul-int/2addr v11, v14
	ushr-long v221, v165, v86
	add-long/2addr v4, v2
	move-wide/from16 v12, v244
	move-wide/from16 v0, v244
	sub-double/2addr v0, v12
	neg-float v0, v10
	add-float v116, v38, v114
	or-int/lit16 v8, v15, -9421
	int-to-byte v10, v6
	xor-int/lit8 v11, v86, -83
	add-double v203, v12, v233
	double-to-long v7, v12
	rem-int/lit16 v3, v11, -21487
	shl-int/2addr v6, v11
	double-to-long v9, v12
	xor-int/2addr v3, v11
	move/from16 v7, v232
	mul-float/2addr v7, v0
	rsub-int v2, v3, 21237
	xor-int/lit16 v12, v15, 16944
	long-to-double v6, v4
	move/from16 v11, v116
	sub-float/2addr v11, v0
	float-to-long v13, v11
	not-int v4, v3
	xor-int/lit16 v0, v15, 3771
	shr-long v145, v149, v117
	sub-long v73, v63, v223
	rsub-int/lit8 v59, v152, 116
	shr-int v75, v142, v163
	or-int/2addr v4, v3
	double-to-int v10, v6
	add-double v131, v17, v181
	mul-int/lit8 v236, v95, 13
	and-long v178, v105, v208
	long-to-double v3, v13
	double-to-float v1, v3
	rem-double v75, v17, v6
	mul-float v20, v38, v11
	not-long v0, v13
	sub-int v186, v91, v250
	float-to-double v9, v11
	neg-int v1, v15
	or-int/lit16 v6, v2, 9867
	mul-int v150, v188, v143
	shr-int v62, v37, v240
	div-float v131, v114, v38
	move-wide/from16 v12, v200
	move-wide/from16 v15, v12
	or-long/2addr v12, v15
	or-int/lit8 v107, v107, 60
	div-int v183, v207, v107
	neg-long v1, v15
	int-to-short v15, v6
	add-long/2addr v1, v12
	sub-long/2addr v12, v1
	const-wide v26, 32L
	or-long v12, v12, v26
	div-long/2addr v1, v12
	sub-int v171, v123, v96
	move/from16 v2, v135
	add-float/2addr v11, v2
	move-wide/from16 v3, v216
	add-long/2addr v12, v3
	shr-int/lit8 v83, v97, 56
	shr-int v180, v84, v243
	sub-float/2addr v2, v11
	sub-float v193, v239, v131
	xor-int v255, v123, v69
	mul-float v126, v232, v151
	div-float/2addr v2, v11
	add-float/2addr v2, v11
	add-float/2addr v11, v2
	double-to-int v12, v9
	and-int/lit8 v183, v164, -100
	or-int v36, v207, v69
	add-int/lit16 v1, v12, -11966
	and-int/lit16 v13, v6, 11452
	or-int/lit8 v13, v13, 89
	div-int/2addr v1, v13
	add-int/lit16 v2, v15, 30867
	int-to-double v7, v13
	not-long v7, v3
	sub-long/2addr v3, v7
	or-long/2addr v7, v3
	sub-int v87, v242, v153
	mul-int/lit8 v100, v153, 97
	const-wide v7, 4096L
	or-long v216, v216, v7
	div-long v108, v200, v216
	neg-int v3, v6
	and-int/lit16 v7, v2, -21575
	float-to-int v3, v11
	move-wide/from16 v6, v263
	long-to-float v5, v6
	add-int/lit16 v4, v3, 20227
	const-wide v178, 262144L
	or-long v63, v63, v178
	rem-long v126, v73, v63
	shl-long v235, v51, v81
	or-int/lit8 v143, v143, 76
	div-int v24, v240, v143
	add-int v10, v95, v242
	add-long v61, v111, v126
	and-int/lit16 v15, v3, 31148
	mul-long v160, v111, v126
	xor-int/lit16 v15, v2, -10514
	sub-long v13, v216, v178
	add-float/2addr v11, v5
	mul-long v186, v223, v120
	div-int/lit16 v0, v12, 27635
	xor-long/2addr v13, v6
	ushr-int v130, v229, v125
	ushr-long v47, v200, v15
	sub-int/2addr v15, v3
	mul-float v199, v202, v42
	move-wide/from16 v15, v244
	double-to-int v15, v15
	or-int/lit8 v241, v43, 86
	mul-float/2addr v5, v11
	or-int/lit8 v36, v36, 34
	div-int v2, v214, v36
	not-int v3, v10
	rem-float v53, v151, v239
	const-wide v6, 2L
	or-long v212, v212, v6
	rem-long v200, v200, v212
	move-wide/from16 v8, v273
	move-wide/from16 v3, v8
	mul-double/2addr v8, v3
	add-long v143, v28, v126
	xor-int/2addr v1, v15
	sub-double/2addr v8, v3
	shl-int/lit8 v86, v58, 35
	and-long/2addr v13, v6
	or-int/lit8 v0, v0, 127
	div-int/2addr v12, v0
	or-int/lit8 v0, v0, 77
	div-int/2addr v1, v0
	sub-float/2addr v11, v5
	neg-int v9, v12
	move-wide/from16 v13, v181
	rem-double/2addr v13, v3
	rem-double v49, v181, v233
	or-int/2addr v12, v0
	or-int/lit8 v127, v98, -37
	shl-int v95, v219, v113
	shl-int/lit8 v216, v55, -123
	add-double/2addr v3, v13
	or-int/lit16 v7, v0, 19337
	int-to-double v5, v9
	add-int/lit16 v5, v0, 16813
	add-float v143, v20, v11
	or-int/lit16 v4, v1, 8325
	div-double v138, v17, v233
	ushr-int/lit8 v243, v137, 22
	move-wide/from16 v1, v26
	move-wide/from16 v10, v267
	xor-long/2addr v10, v1
	move/from16 v1, v193
	float-to-int v2, v1
	mul-float v120, v239, v135
	add-float v35, v239, v193
	move/from16 v14, v135
	div-float/2addr v1, v14
	mul-int v29, v168, v25
	move-wide/from16 v9, v105
	move-wide/from16 v5, v225
	add-long/2addr v5, v9
	rem-float/2addr v1, v14
	int-to-double v11, v4
	mul-float v171, v42, v193
	move-wide/from16 v8, v227
	mul-double/2addr v11, v8
	double-to-float v7, v11
	shl-int v13, v137, v0
	rem-int/lit16 v1, v0, -2320
	shl-int/2addr v1, v4
	rem-int/lit16 v13, v0, -29812
	or-int/lit8 v13, v13, 13
	rem-int/2addr v15, v13
	long-to-double v4, v5
	add-double/2addr v11, v8
	or-int/lit8 v196, v196, 80
	div-int v24, v142, v196
	div-int/lit16 v12, v1, 24134
	move-wide/from16 v9, v108
	long-to-float v4, v9
	or-int/lit8 v163, v163, 104
	div-int v25, v81, v163
	xor-long v125, v111, v63
	const-wide v2, 0x786dbcd2cb8c7bbcL
	or-long/2addr v2, v9
	div-float/2addr v14, v7
	mul-long/2addr v2, v9
	int-to-float v8, v12
	rem-int/lit16 v12, v1, -18957
	const-wide v145, 1024L
	or-long v189, v189, v145
	div-long v187, v223, v189
	rem-double v54, v227, v181
	rem-int/lit16 v9, v12, 1562
	move-wide/from16 v11, v49
	double-to-float v11, v11
	sub-float/2addr v11, v14
	ushr-int v103, v249, v107
	or-int/lit16 v9, v1, 31373
	xor-long v249, v26, v61
	const-wide v12, 0xc3fe59e6900ffa70L
	const-wide v51, 64L
	or-long v2, v2, v51
	div-long/2addr v12, v2
	rsub-int v4, v0, 12404
	int-to-char v11, v1
	mul-int/2addr v4, v15
	shr-int/lit8 v81, v1, -64
	add-long v15, v61, v249
	or-int/lit8 v44, v44, 34
	rem-int v190, v23, v44
	int-to-long v1, v9
	add-float v64, v199, v131
	int-to-char v14, v11
	sub-float/2addr v8, v7
	ushr-long/2addr v15, v9
	mul-int/2addr v4, v0
	or-int/lit16 v8, v14, -4224
	shl-long/2addr v12, v4
	xor-int/2addr v4, v9
	move-wide/from16 v0, v203
	move-wide/from16 v12, v203
	rem-double/2addr v12, v0
	sub-double/2addr v12, v0
	xor-int/2addr v9, v14
	int-to-float v3, v4
	not-int v4, v9
	move-wide/from16 v13, v267
	xor-long/2addr v15, v13
	div-int/lit16 v12, v11, 22921
	xor-int/2addr v9, v12
	or-int/lit8 v12, v12, 34
	div-int/2addr v9, v12
	mul-int/2addr v9, v8
	rem-int/lit16 v13, v4, 23470
	int-to-byte v8, v13
	int-to-char v12, v11
	or-int/lit8 v225, v44, 70
	div-double v239, v244, v138
	double-to-int v9, v0
	or-int v254, v180, v8
	xor-int v77, v93, v110
	add-float/2addr v3, v7
	rsub-int/lit8 v125, v123, 106
	int-to-float v13, v4
	or-int v69, v21, v198
	mul-float/2addr v7, v13
	long-to-int v4, v15
	int-to-byte v14, v12
	div-int/lit8 v58, v150, -31
	ushr-long/2addr v15, v8
	ushr-long/2addr v15, v4
	move-wide/from16 v2, v51
	const-wide v32, 262144L
	or-long v15, v15, v32
	div-long/2addr v2, v15
	int-to-short v15, v9
	shl-int/2addr v14, v4
	not-long v7, v2
	and-int/lit16 v14, v14, -22073
	sub-long/2addr v2, v7
	or-long v210, v221, v249
	int-to-short v12, v11
	neg-float v6, v13
	mul-double v29, v239, v244
	ushr-int/2addr v11, v9
	sub-int/2addr v11, v15
	rem-float/2addr v13, v6
	ushr-long/2addr v2, v9
	const-wide v230, 524288L
	or-long v7, v7, v230
	rem-long/2addr v2, v7
	int-to-short v14, v12
	ushr-int v166, v242, v14
	mul-long/2addr v2, v7
	add-int/2addr v11, v14
	and-int/lit8 v240, v229, 1
	div-double v184, v181, v138
	shl-int/2addr v15, v14
	or-int/lit8 v254, v103, 69
	sub-long v115, v47, v61
	or-int v188, v93, v36
	add-int/lit8 v167, v21, 61
	and-int/2addr v4, v12
	not-long v5, v7
	xor-long/2addr v7, v2
	const-wide v247, 32768L
	or-long v247, v247, v247
	rem-long v228, v212, v247
	move-wide/from16 v11, v184
	div-double/2addr v11, v0
	mul-int/2addr v14, v9
	mul-long/2addr v2, v5
	int-to-double v13, v4
	mul-int/lit8 v135, v40, -24
	or-long v121, v228, v32
	sub-int v144, v41, v65
	int-to-char v3, v9
	add-int v2, v150, v97
	const-wide v160, 4L
	or-long v228, v228, v160
	rem-long v25, v51, v228
	ushr-long/2addr v5, v4
	add-int v209, v2, v69
	or-long v250, v73, v200
	rem-float v151, v129, v42
	mul-int/lit8 v11, v78, 81
	int-to-double v0, v2
	move/from16 v6, v35
	move/from16 v7, v35
	sub-float/2addr v6, v7
	sub-double v147, v13, v138
	xor-int v255, v240, v153
	xor-int/2addr v3, v11
	ushr-int v33, v93, v96
	const-wide v15, 0xf944a9eb03c6299dL
	move-wide/from16 v8, v121
	sub-long/2addr v15, v8
	and-int/lit16 v12, v3, -7784
	and-int/2addr v12, v11
	sub-long v137, v8, v115
	ushr-long v206, v221, v209
	rem-int/lit8 v113, v196, 109
	xor-int/lit16 v8, v11, -32527
	rsub-int v6, v12, -24970
	div-float v207, v131, v42
	add-long v208, v228, v51
	xor-int v119, v167, v78
	xor-int/lit8 v12, v65, -5
	div-double v177, v0, v49
	not-int v15, v2
	sub-long v19, v73, v228
	const-wide v47, 16777216L
	or-long v247, v247, v47
	rem-long v144, v121, v247
	move-wide/from16 v4, v250
	shr-long/2addr v4, v11
	or-int/lit8 v23, v23, 94
	div-int v190, v86, v23
	div-float v143, v35, v171
	not-int v10, v6
	ushr-long v25, v61, v219
	mul-double/2addr v13, v0
	neg-double v11, v0
	or-int/2addr v8, v15
	or-int v92, v152, v130
	rem-int/lit8 v222, v78, -1
	or-int/lit8 v3, v3, 19
	rem-int/2addr v2, v3
	long-to-int v12, v4
	div-float v39, v42, v38
	const-wide v160, 16777216L
	or-long v115, v115, v160
	div-long v253, v137, v115
	const-wide v108, 8L
	or-long v173, v173, v108
	div-long v176, v19, v173
	double-to-float v9, v0
	sub-double v142, v54, v203
	move-wide/from16 v7, v253
	const-wide v250, 4L
	or-long v7, v7, v250
	rem-long/2addr v4, v7
	rem-float v212, v114, v72
	add-float v60, v212, v39
	add-int/lit8 v210, v113, -64
	const-wide v7, 32768L
	or-long v250, v250, v7
	div-long v146, v51, v250
	not-int v14, v6
	double-to-int v1, v0
	int-to-char v6, v14
	or-int/lit16 v0, v1, 6311
	int-to-float v9, v6
	add-int/lit8 v169, v2, -87
	ushr-int/lit8 v185, v103, 46
	move/from16 v8, v60
	sub-float/2addr v9, v8
	ushr-long/2addr v4, v0
	float-to-int v10, v8
	sub-int/2addr v10, v14
	mul-int/2addr v1, v12
	and-int/lit16 v12, v14, -9269
	ushr-int v71, v135, v15
	sub-float v2, v193, v38
	move-wide/from16 v4, v121
	move-wide/from16 v3, v265
	move-wide/from16 v10, v173
	const-wide v144, 536870912L
	or-long v3, v3, v144
	rem-long/2addr v10, v3
	rem-float/2addr v8, v2
	or-int/lit8 v218, v218, 84
	rem-int v2, v37, v218
	and-int v31, v14, v219
	int-to-short v10, v14
	add-double v138, v181, v142
	add-long v234, v51, v47
	shl-long v112, v253, v12
	not-long v1, v3
	and-long/2addr v3, v1
	rem-float/2addr v8, v9
	xor-long v179, v61, v51
	xor-int/lit8 v32, v93, 76
	and-int/2addr v0, v14
	or-int v154, v33, v21
	rem-double v224, v138, v54
	shl-long v86, v173, v87
	or-int/lit8 v92, v92, 77
	div-int v63, v135, v92
	rem-int/lit8 v220, v242, -11
	or-int/lit8 v15, v15, 91
	div-int/2addr v14, v15
	long-to-float v8, v3
	rem-float v49, v232, v72
	add-double v188, v142, v17
	or-long/2addr v1, v3
	ushr-long v209, v73, v191
	sub-long v10, v73, v144
	or-int v234, v94, v119
	move-wide/from16 v5, v271
	move-wide/from16 v6, v75
	move-wide/from16 v11, v17
	rem-double/2addr v6, v11
	int-to-long v3, v15
	sub-double v52, v181, v138
	or-long/2addr v3, v1
	div-double v65, v54, v52
	neg-long v12, v3
	sub-float v206, v39, v60
	xor-long v110, v25, v250
	sub-float v72, v64, v151
	double-to-float v0, v6
	div-float/2addr v0, v8
	rem-float/2addr v0, v8
	long-to-int v15, v12
	or-int/2addr v15, v14
	sub-int/2addr v14, v15
	ushr-long v37, v3, v133
	int-to-char v10, v15
	ushr-int/lit8 v63, v220, -90
	rem-float/2addr v8, v9
	add-int/2addr v10, v15
	rsub-int/lit8 v153, v40, -103
	mul-double v230, v65, v181
	move-wide/from16 v3, v203
	div-double/2addr v6, v3
	rem-int/lit8 v46, v157, 42
	div-double/2addr v6, v3
	int-to-char v4, v10
	shl-long/2addr v1, v4
	xor-int/lit8 v98, v191, -96
	add-double v175, v54, v138
	and-int v167, v22, v155
	not-int v4, v10
	shr-int/2addr v4, v14
	shl-int v119, v67, v59
	add-int/2addr v15, v4
	div-int/lit8 v127, v242, -36
	const-wide v253, 16777216L
	or-long v12, v12, v253
	div-long/2addr v1, v12
	or-int/lit8 v15, v15, 7
	div-int/2addr v10, v15
	add-int v53, v24, v10
	add-long/2addr v12, v1
	and-long/2addr v1, v12
	sub-int v44, v134, v83
	sub-float v32, v64, v114
	mul-int/2addr v15, v14
	long-to-float v7, v1
	sub-long/2addr v12, v1
	const-wide v47, 33554432L
	or-long v12, v12, v47
	rem-long/2addr v1, v12
	div-float v79, v199, v129
	div-int/lit16 v3, v14, 30993
	not-long v15, v1
	or-int/lit8 v97, v97, 20
	rem-int v226, v46, v97
	shl-int/2addr v10, v3
	rem-float v199, v151, v120
	mul-long/2addr v12, v15
	mul-long/2addr v12, v1
	const-wide v247, 8388608L
	or-long v110, v110, v247
	div-long v72, v86, v110
	move-wide/from16 v10, v142
	double-to-float v9, v10
	and-long v169, v228, v1
	int-to-byte v1, v3
	ushr-long v51, v250, v130
	neg-float v9, v0
	move-wide/from16 v11, v138
	move-wide/from16 v13, v142
	add-double/2addr v11, v13
	div-float/2addr v9, v8
	not-long v12, v15
	rsub-int/lit8 v8, v226, 33
	float-to-double v5, v0
	shr-int/2addr v1, v4
	and-long v216, v110, v37
	mul-float v225, v131, v120
	shr-long/2addr v12, v1
	neg-long v5, v12
	or-int/lit16 v1, v8, -14987
	add-long v129, v105, v51
	add-long/2addr v5, v12
	float-to-double v9, v0
	or-int/lit8 v3, v3, 107
	div-int/2addr v4, v3
	shr-int/2addr v1, v4
	shr-int v17, v97, v135
	ushr-int/2addr v8, v4
	add-int/lit8 v39, v21, -38
	add-int/lit8 v98, v155, -12
	mul-int/lit16 v4, v4, 612
	move-wide/from16 v2, v54
	add-double/2addr v9, v2
	double-to-long v9, v2
	float-to-double v6, v0
	const-wide v179, 16L
	or-long v129, v129, v179
	rem-long v242, v9, v129
	sub-double v33, v65, v54
	rsub-int/lit8 v238, v166, -62
	xor-int/lit16 v10, v4, 11885
	xor-int v122, v133, v252
	sub-long v127, v86, v108
	neg-float v10, v0
	xor-long/2addr v15, v12
	ushr-int v51, v95, v117
	mul-int/2addr v4, v8
	mul-double/2addr v2, v6
	rem-float/2addr v0, v10
	and-int v93, v94, v152
	ushr-long v61, v110, v39
	int-to-short v14, v8
	shl-long/2addr v15, v4
	div-float v235, v60, v193
	and-int v183, v119, v185
	const-wide v247, 64L
	or-long v105, v105, v247
	div-long v169, v209, v105
	sub-long/2addr v15, v12
	float-to-long v11, v0
	mul-float v125, v206, v60
	xor-int/lit8 v74, v215, 39
	mul-float/2addr v0, v10
	sub-int/2addr v14, v8
	ushr-int v192, v40, v123
	double-to-int v0, v2
	add-int v116, v154, v153
	add-long/2addr v15, v11
	int-to-byte v8, v0
	add-long/2addr v11, v15
	mul-long/2addr v15, v11
	div-int/lit16 v5, v1, 30551
	shl-long v210, v25, v51
	shl-int/lit8 v85, v94, 86
	neg-long v15, v15
	xor-int v38, v238, v69
	div-int/lit16 v13, v1, 13725
	rem-double v236, v2, v181
	and-int/lit16 v15, v1, -24701
	add-double v44, v230, v6
	move-wide/from16 v9, v47
	sub-long/2addr v9, v11
	or-int/lit8 v220, v220, 26
	rem-int v90, v67, v220
	move/from16 v15, v79
	move/from16 v6, v207
	rem-float/2addr v6, v15
	float-to-double v11, v15
	xor-int/2addr v8, v5
	shl-int/2addr v0, v1
	ushr-int/2addr v1, v0
	neg-float v12, v6
	shr-int/2addr v0, v4
	shl-long/2addr v9, v8
	move-wide/from16 v0, v54
	rem-double/2addr v0, v2
	move-wide/from16 v13, v112
	and-long/2addr v13, v9
	double-to-long v0, v0
	shl-long v104, v47, v83
	xor-int v52, v215, v117
	float-to-double v8, v12
	mul-long v83, v108, v61
	or-int/lit8 v79, v168, -80
	ushr-long/2addr v13, v5
	long-to-int v6, v13
	neg-double v1, v2
	move-wide/from16 v7, v265
	mul-long/2addr v7, v13
	or-long/2addr v7, v13
	mul-int/lit16 v8, v6, 3984
	float-to-double v8, v12
	int-to-double v1, v4
	add-double v172, v236, v230
	div-float v198, v125, v131
	move-wide/from16 v14, v72
	move-wide/from16 v9, v61
	mul-long/2addr v14, v9
	mul-double v217, v138, v1
	sub-long/2addr v9, v14
	move/from16 v2, v232
	sub-float/2addr v2, v12
	and-int v252, v85, v53
	not-long v12, v14
	neg-int v1, v4
	int-to-byte v8, v4
	long-to-float v9, v14
	or-int/2addr v5, v6
	div-double v198, v181, v172
	add-int v216, v154, v196
	mul-long v73, v179, v83
	rsub-int/lit8 v250, v103, 117
	const-wide v104, 524288L
	or-long v12, v12, v104
	div-long/2addr v14, v12
	long-to-double v6, v12
	xor-int v195, v93, v96
	and-int/lit8 v153, v166, -102
	move-wide/from16 v8, v172
	add-double/2addr v8, v6
	neg-float v11, v2
	rsub-int v0, v4, -11767
	rsub-int v9, v5, -18517
	add-int/lit16 v0, v1, 31282
	double-to-long v9, v6
	or-long v67, v19, v210
	sub-long/2addr v12, v14
	int-to-long v12, v1
	or-int/lit8 v244, v241, 34
	const-wide v112, 4L
	or-long v9, v9, v112
	div-long/2addr v12, v9
	sub-float v196, v42, v193
	rem-double v213, v29, v188
	mul-int/lit16 v4, v0, -27013
	mul-float/2addr v2, v11
	rem-int/lit8 v201, v240, 54
	int-to-short v12, v1
	ushr-long/2addr v14, v0
	div-float/2addr v2, v11
	div-int/lit8 v141, v240, -95
	neg-int v8, v5
	rem-float/2addr v11, v2
	move-wide/from16 v7, v271
	move-wide/from16 v7, v273
	move-wide/from16 v11, v271
	rem-double/2addr v11, v7
	or-int/2addr v0, v4
	int-to-char v0, v5
	div-double v182, v213, v75
	xor-int/lit16 v2, v1, 15370
	sub-double/2addr v7, v11
	rem-int/lit8 v151, v4, 35
	double-to-float v13, v7
	sub-float v27, v13, v171
	ushr-int/2addr v4, v0
	rem-int/lit8 v32, v244, -128
	shl-int v240, v94, v168
	rem-double v171, v188, v236
	rem-float v157, v207, v131
	or-int/2addr v0, v4
	and-long v225, v242, v25
	ushr-long v195, v47, v103
	double-to-long v13, v7
	xor-int/lit8 v157, v117, 94
	ushr-long/2addr v13, v0
	add-int/2addr v5, v2
	xor-long/2addr v9, v13
	or-long v36, v247, v146
	double-to-float v11, v7
	const-wide v144, 8L
	or-long v13, v13, v144
	rem-long/2addr v9, v13
	move/from16 v1, v232
	add-float/2addr v11, v1
	neg-double v10, v7
	move/from16 v1, v64
	move/from16 v10, v262
	rem-float/2addr v10, v1
	move-wide/from16 v5, v225
	const-wide v13, 8388608L
	or-long v13, v13, v13
	div-long/2addr v5, v13
	add-int/lit8 v98, v255, 85
	mul-long v37, v169, v108
	add-float v194, v114, v10
	int-to-float v7, v0
	xor-int v229, v69, v255
	and-long v52, v179, v146
	not-int v3, v0
	shl-long v64, v129, v255
	mul-double v79, v188, v54
	int-to-short v7, v0
	or-int/lit8 v119, v119, 66
	div-int v13, v71, v119
	ushr-long/2addr v5, v0
	shl-int/2addr v0, v4
	shl-int/lit8 v160, v150, 2
	xor-long v203, v104, v146
	or-int/lit8 v82, v167, 104
	ushr-long/2addr v5, v3
	or-int/lit16 v4, v13, -18337
	and-int/2addr v0, v3
	and-int/lit16 v0, v7, -1862
	ushr-int v7, v133, v238
	sub-int/2addr v13, v4
	int-to-byte v9, v13
	move-wide/from16 v6, v47
	move-wide/from16 v10, v210
	const-wide v37, 256L
	or-long v10, v10, v37
	div-long/2addr v6, v10
	or-int v65, v229, v160
	shl-int v38, v4, v240
	or-long/2addr v10, v6
	add-int/2addr v3, v2
	div-int/lit16 v4, v9, 20893
	or-int/lit8 v4, v4, 86
	rem-int/2addr v3, v4
	add-int/2addr v4, v2
	not-int v10, v4
	shl-int v104, v63, v21
	neg-float v8, v1
	and-int/lit8 v182, v10, 45
	sub-float/2addr v8, v1
	move-wide/from16 v5, v179
	move-wide/from16 v14, v129
	xor-long/2addr v14, v5
	long-to-int v9, v14
	int-to-short v4, v13
	xor-int v10, v40, v9
	or-int/lit16 v11, v9, 27390
	sub-int/2addr v4, v13
	mul-int v139, v71, v150
	neg-int v1, v9
	mul-float v180, v60, v235
	float-to-long v7, v8
	shr-int v148, v215, v222
	or-int/lit16 v6, v3, -22970
	shr-long v207, v7, v38
	add-double v32, v236, v142
	int-to-short v2, v1
	sub-long v189, v73, v207
	move/from16 v5, v49
	move/from16 v12, v114
	add-float/2addr v12, v5
	sub-float v100, v42, v120
	div-int/lit16 v4, v4, 12876
	div-int/lit8 v177, v166, -43
	mul-long/2addr v7, v14
	add-int/lit8 v143, v168, -30
	mul-int/lit16 v7, v6, 29357
	add-int/2addr v11, v10
	rem-int/lit16 v5, v7, -13966
	neg-float v3, v12
	mul-float v185, v193, v27
	const-wide v225, 2048L
	or-long v14, v14, v225
	rem-long v130, v169, v14
	mul-long v242, v108, v61
	or-int v73, v167, v11
	div-int/lit16 v3, v5, -30943
	float-to-long v6, v12
	shr-int/lit8 v243, v70, 103
	move-wide/from16 v5, v29
	move-wide/from16 v14, v79
	sub-double/2addr v5, v14
	or-int/lit8 v22, v22, 46
	rem-int v106, v38, v22
	rem-double/2addr v5, v14
	move-wide/from16 v7, v67
	move-wide/from16 v4, v130
	sub-long/2addr v7, v4
	move/from16 v6, v193
	sub-float/2addr v6, v12
	mul-int/2addr v10, v0
	double-to-float v9, v14
	and-int/2addr v13, v2
	sub-float/2addr v9, v12
	neg-double v2, v14
	rsub-int/lit8 v70, v103, -24
	long-to-double v2, v7
	neg-float v1, v12
	mul-long/2addr v7, v4
	shr-int/2addr v13, v0
	and-int/lit16 v7, v0, -15311
	rem-float v182, v232, v206
	rem-int/lit16 v3, v10, -11005
	ushr-long v156, v110, v122
	xor-int/lit16 v7, v11, -19736
	sub-float v39, v202, v60
	sub-int v130, v24, v234
	and-long v44, v225, v112
	neg-int v1, v11
	ushr-int/lit8 v28, v21, 99
	or-long v148, v207, v52
	or-int/lit8 v250, v250, 49
	div-int v66, v241, v250
	int-to-float v5, v11
	move-wide/from16 v15, v127
	move-wide/from16 v14, v112
	move-wide/from16 v5, v47
	const-wide v203, 64L
	or-long v14, v14, v203
	rem-long/2addr v5, v14
	or-int/lit8 v10, v10, 56
	rem-int/2addr v13, v10
	add-int/lit8 v216, v66, -95
	div-float/2addr v12, v9
	mul-int/lit16 v6, v7, 13623
	rsub-int v11, v7, -8598
	rsub-int/lit8 v253, v119, 0
	add-int v236, v96, v103
	xor-int/lit8 v183, v65, -127
	and-int/2addr v10, v3
	move-wide/from16 v1, v54
	double-to-long v0, v1
	shr-long/2addr v14, v13
	float-to-double v4, v9
	add-long v95, v67, v110
	or-long/2addr v14, v0
	add-float v191, v120, v49
	move-wide/from16 v7, v198
	add-double/2addr v4, v7
	xor-int v243, v70, v78
	div-float v113, v120, v182
	div-float/2addr v12, v9
	or-int/lit16 v8, v11, -27080
	int-to-double v10, v6
	add-float v44, v235, v60
	shl-long v222, v189, v116
	or-int/lit8 v139, v63, 23
	int-to-long v6, v3
	xor-int/lit8 v217, v240, 13
	and-int/lit8 v49, v117, -17
	and-long v76, v52, v210
	add-float/2addr v12, v9
	rem-int/lit16 v13, v13, -8126
	const-wide v67, 32768L
	or-long v148, v148, v67
	rem-long v55, v61, v148
	xor-int v197, v119, v78
	shl-long/2addr v0, v13
	and-long v33, v222, v203
	add-int/lit16 v1, v8, -27825
	or-int/lit8 v13, v13, 124
	rem-int/2addr v8, v13
	sub-long v109, v86, v207
	sub-long v172, v33, v222
	or-int/lit16 v15, v1, -14548
	add-int/2addr v13, v8
	move-wide/from16 v12, v6
	and-long/2addr v12, v6
	double-to-float v4, v10
	ushr-int/2addr v15, v8
	int-to-short v3, v1
	neg-double v8, v10
	or-long/2addr v12, v6
	sub-long v149, v76, v12
	and-int v164, v63, v117
	double-to-int v13, v8
	xor-long v202, v67, v222
	sub-int/2addr v3, v15
	shr-int/lit8 v233, v236, -5
	add-double/2addr v10, v8
	mul-float v96, v39, v60
	div-double/2addr v10, v8
	and-int v223, v240, v234
	mul-int/lit16 v5, v1, -26845
	shr-int v198, v154, v1
	mul-int v79, v1, v229
	add-float v0, v235, v114
	and-int/2addr v3, v1
	rsub-int/lit8 v132, v122, 42
	sub-long v206, v210, v225
	and-int/2addr v3, v5
	and-int/2addr v5, v13
	ushr-long/2addr v6, v15
	move-wide/from16 v10, v144
	and-long/2addr v6, v10
	move-wide/from16 v2, v269
	sub-double/2addr v2, v8
	mul-double v168, v2, v213
	or-int/lit8 v90, v90, 76
	div-int v153, v160, v90
	or-int/lit8 v5, v5, 66
	div-int/2addr v15, v5
	neg-int v13, v5
	neg-long v10, v6
	int-to-byte v6, v5
	int-to-char v14, v6
	ushr-long/2addr v10, v6
	add-float v242, v125, v42
	shr-long v220, v146, v167
	neg-int v8, v1
	neg-double v5, v2
	float-to-double v10, v4
	xor-int/lit16 v1, v8, -15758
	const-wide v12, 0xef06ff2991744a7bL
	move-wide/from16 v12, v247
	move-wide/from16 v2, v33
	const-wide v33, 1073741824L
	or-long v12, v12, v33
	rem-long/2addr v2, v12
	and-int/lit16 v7, v8, -16904
	xor-int/lit16 v2, v7, 7888
	or-long v196, v33, v83
	or-int/lit8 v27, v82, -3
	int-to-double v0, v15
	rsub-int v7, v7, -25478
	not-int v3, v7
	int-to-long v5, v15
	rem-int/lit16 v4, v8, -12037
	or-int/lit8 v4, v4, 79
	rem-int v141, v192, v4
	double-to-long v1, v0
	rem-int/lit8 v202, v160, -57
	or-long/2addr v1, v5
	add-int v115, v104, v91
	add-float v64, v113, v96
	or-int v163, v91, v85
	const-wide v196, 262144L
	or-long v12, v12, v196
	div-long/2addr v1, v12
	shl-int/lit8 v153, v65, 0
	const-wide v25, 4L
	or-long v206, v206, v25
	rem-long v101, v52, v206
	xor-int/2addr v14, v4
	sub-long/2addr v1, v5
	double-to-int v10, v10
	int-to-short v14, v7
	move/from16 v10, v114
	float-to-double v13, v10
	const-wide v101, 16384L
	or-long v1, v1, v101
	div-long/2addr v5, v1
	neg-double v15, v13
	const-wide v86, 67108864L
	or-long v5, v5, v86
	div-long/2addr v1, v5
	long-to-int v14, v1
	int-to-short v13, v14
	mul-int v112, v17, v41
	neg-double v15, v15
	and-long v108, v149, v144
	xor-long v163, v196, v101
	float-to-int v5, v10
	double-to-long v5, v15
	int-to-double v0, v7
	const-wide v5, 8192L
	or-long v220, v220, v5
	rem-long v153, v206, v220
	shr-int/2addr v14, v8
	rem-float v86, v44, v185
	move/from16 v8, v182
	sub-float/2addr v10, v8
	mul-int/lit16 v4, v14, 31483
	and-int/lit8 v154, v238, -45
	rem-int/lit8 v24, v133, -56
	double-to-float v13, v15
	shr-int/2addr v4, v7
	xor-long v238, v33, v206
	mul-double/2addr v0, v15
	add-float v78, v185, v96
	double-to-long v1, v15
	and-long/2addr v1, v5
	sub-float v5, v182, v180
	add-float/2addr v8, v10
	shl-int v77, v70, v132
	xor-int/lit16 v3, v4, 13855
	move-wide/from16 v5, v263
	and-long/2addr v5, v1
	add-long v141, v33, v210
	float-to-int v2, v10
	shr-int/lit8 v86, v41, 115
	and-int v90, v63, v79
	add-float/2addr v10, v8
	and-int/lit16 v4, v14, -10509
	move-wide/from16 v5, v206
	move-wide/from16 v0, v141
	mul-long/2addr v5, v0
	rem-float/2addr v13, v8
	shr-int/2addr v3, v7
	shr-int/lit8 v240, v155, 107
	shr-long v253, v163, v223
	const-wide v127, 16777216L
	or-long v5, v5, v127
	rem-long/2addr v0, v5
	int-to-float v14, v14
	rsub-int v0, v2, -30834
	move-wide/from16 v2, v267
	const-wide v61, 64L
	or-long v5, v5, v61
	div-long/2addr v2, v5
	and-int/lit16 v4, v7, -23153
	xor-long v196, v149, v172
	or-int/lit8 v4, v4, 4
	div-int/2addr v7, v4
	sub-long v165, v25, v19
	double-to-int v4, v15
	and-int v26, v243, v107
	double-to-int v10, v15
	xor-long/2addr v2, v5
	mul-float/2addr v14, v13
	or-int/lit8 v7, v7, 87
	rem-int/2addr v0, v7
	ushr-int/2addr v0, v4
	add-int/2addr v7, v0
	div-int/lit8 v45, v234, 97
	move-wide/from16 v9, v271
	add-double/2addr v9, v15
	add-long v191, v61, v52
	neg-float v15, v13
	int-to-double v2, v4
	or-int v89, v82, v90
	or-int/lit8 v26, v26, 27
	rem-int v213, v45, v26
	rem-float/2addr v14, v13
	or-int/lit8 v114, v217, -107
	or-int/2addr v0, v4
	div-double v97, v29, v175
	int-to-short v3, v4
	add-float/2addr v14, v13
	mul-int/lit16 v4, v7, -24119
	and-int/2addr v4, v0
	rem-double v70, v97, v29
	int-to-short v14, v7
	int-to-long v10, v0
	shl-int v81, v123, v94
	mul-long/2addr v5, v10
	rem-float v154, v42, v64
	ushr-long v130, v191, v82
	add-double v8, v70, v97
	shr-int/lit8 v112, v233, 125
	and-int/2addr v4, v3
	ushr-int v40, v233, v94
	or-int/lit8 v14, v14, 88
	div-int/2addr v7, v14
	sub-float v10, v39, v242
	mul-float v128, v194, v232
	int-to-long v14, v0
	sub-double v33, v29, v97
	mul-double v205, v33, v8
	ushr-int/lit8 v136, v59, -113
	double-to-int v7, v8
	sub-float v124, v44, v120
	long-to-double v9, v14
	move-wide/from16 v1, v33
	sub-double/2addr v1, v9
	int-to-byte v13, v7
	sub-double/2addr v9, v1
	and-int v137, v229, v243
	or-int/lit8 v92, v92, 16
	div-int v208, v13, v92
	shl-int/2addr v0, v7
	xor-int v241, v155, v177
	const-wide v220, 512L
	or-long v19, v19, v220
	div-long v121, v172, v19
	div-double v8, v29, v33
	add-long/2addr v14, v5
	rem-int/lit16 v4, v3, 8700
	long-to-float v12, v5
	or-int/lit8 v4, v4, 37
	div-int/2addr v0, v4
	div-int/lit8 v156, v223, 26
	shl-int/lit8 v93, v0, 30
	ushr-long/2addr v14, v7
	int-to-long v11, v13
	long-to-float v11, v5
	add-int/lit16 v15, v3, -23822
	const-wide v144, 2097152L
	or-long v5, v5, v144
	div-long v151, v238, v5
	shr-long/2addr v5, v4
	div-double/2addr v8, v1
	mul-float v216, v182, v128
	ushr-long/2addr v5, v3
	int-to-long v11, v13
	neg-double v8, v8
	or-int/2addr v13, v0
	or-int/2addr v4, v7
	add-int/lit16 v12, v15, 30551
	sub-long v171, v189, v165
	add-double/2addr v8, v1
	const-wide v19, 65536L
	or-long v189, v189, v19
	div-long v131, v225, v189
	move/from16 v10, v64
	move/from16 v12, v44
	div-float/2addr v12, v10
	add-float v242, v235, v185
	mul-long v7, v210, v247
	mul-long v202, v171, v191
	div-double v154, v29, v33
	rem-int/lit16 v10, v3, -22479
	ushr-int/2addr v0, v15
	ushr-int v67, v4, v114
	long-to-double v13, v5
	int-to-float v2, v4
	int-to-short v6, v10
	div-float v105, v194, v64
	not-long v6, v7
	shr-long v10, v165, v156
	xor-long v4, v131, v238
	and-int/lit16 v12, v15, 2825
	neg-float v15, v2
	sub-float/2addr v15, v2
	add-int/2addr v3, v0
	sub-int v181, v107, v143
	float-to-long v4, v15
	int-to-long v7, v3
	neg-long v10, v7
	int-to-byte v1, v3
	move-wide/from16 v0, v271
	div-double/2addr v0, v13
	add-float v114, v96, v124
	or-int/lit8 v3, v3, 88
	div-int/2addr v12, v3
	xor-int/2addr v12, v3
	add-int/2addr v12, v3
	const-wide v55, 2L
	or-long v10, v10, v55
	rem-long v200, v47, v10
	shr-int/2addr v12, v3
	add-int v142, v229, v183
	ushr-int/lit8 v180, v115, -39
	double-to-int v11, v0
	and-int/lit16 v4, v12, -12186
	rem-int/lit16 v0, v12, 22229
	div-double v126, v13, v230
	and-long v138, v144, v253
	add-double v245, v126, v70
	int-to-float v7, v0
	add-long v197, v55, v171
	ushr-int/2addr v12, v0
	xor-int v54, v65, v63
	move-wide/from16 v4, v52
	long-to-float v15, v4
	move-wide/from16 v13, v210
	and-long/2addr v4, v13
	sub-long/2addr v4, v13
	rsub-int v1, v12, -21075
	div-float v128, v235, v194
	mul-long/2addr v4, v13
	shr-long/2addr v13, v1
	or-int/lit8 v12, v12, 5
	rem-int/2addr v3, v12
	and-long/2addr v13, v4
	move-wide/from16 v6, v29
	double-to-long v12, v6
	ushr-int v31, v123, v93
	ushr-long v155, v200, v233
	mul-int/lit16 v8, v1, -13091
	mul-int/lit8 v164, v112, 49
	add-float v25, v114, v64
	long-to-int v6, v4
	and-int/lit16 v7, v1, -6591
	neg-float v3, v2
	xor-long/2addr v4, v12
	shr-long v158, v191, v31
	and-int/lit16 v1, v11, 8176
	ushr-int v60, v66, v85
	rem-int/lit8 v101, v23, -106
	neg-long v13, v4
	move-wide/from16 v12, v273
	move-wide/from16 v15, v126
	add-double/2addr v15, v12
	move-wide/from16 v9, v4
	const-wide v19, 8192L
	or-long v9, v9, v19
	rem-long/2addr v4, v9
	shl-int/lit8 v123, v117, 94
	shr-int v181, v215, v233
	neg-int v13, v0
	int-to-float v15, v7
	rem-double v109, v97, v70
	float-to-long v10, v15
	int-to-double v10, v7
	and-long v17, v171, v200
	xor-int/lit16 v3, v13, -32147
	add-int v136, v101, v90
	add-int v191, v164, v240
	move-wide/from16 v1, v126
	add-double/2addr v1, v10
	not-int v14, v13
	int-to-char v10, v0
	and-int/lit8 v207, v89, 5
	sub-int/2addr v14, v13
	ushr-long/2addr v4, v0
	rem-double v215, v70, v175
	move-wide/from16 v15, v1
	sub-double/2addr v15, v1
	mul-int/2addr v7, v0
	const-wide v144, 2L
	or-long v220, v220, v144
	div-long v111, v47, v220
	rsub-int/lit8 v73, v233, -14
	const-wide v189, 65536L
	or-long v155, v155, v189
	div-long v158, v83, v155
	move/from16 v3, v120
	float-to-double v12, v3
	or-int/lit16 v11, v6, -16798
	not-int v14, v14
	move/from16 v5, v39
	sub-float/2addr v5, v3
	const-wide v210, 32L
	or-long v144, v144, v210
	div-long v224, v197, v144
	rem-float v178, v120, v78
	add-long v114, v131, v155
	add-double v90, v230, v109
	neg-int v7, v8
	mul-int v120, v77, v40
	add-int/lit8 v96, v191, -43
	int-to-char v7, v7
	move-wide/from16 v1, v121
	move-wide/from16 v0, v220
	move-wide/from16 v13, v155
	const-wide v171, 134217728L
	or-long v0, v0, v171
	rem-long/2addr v13, v0
	float-to-double v4, v3
	or-int/lit8 v7, v7, 83
	rem-int/2addr v6, v7
	shr-long/2addr v13, v11
	mul-float v116, v39, v25
	sub-double/2addr v15, v4
	int-to-short v0, v7
	not-long v11, v13
	long-to-float v8, v11
	mul-int/2addr v7, v10
	add-int/lit16 v14, v7, -24135
	move-wide/from16 v6, v83
	add-long/2addr v6, v11
	xor-int/lit16 v3, v0, -2661
	or-long/2addr v6, v11
	mul-double v205, v109, v15
	mul-double v47, v15, v126
	rem-int/lit16 v11, v10, -5036
	neg-double v15, v4
	not-int v10, v3
	rsub-int v2, v14, 4653
	move/from16 v14, v194
	mul-float/2addr v14, v8
	move-wide/from16 v9, v265
	sub-long/2addr v9, v6
	const-wide v131, 8L
	or-long v6, v6, v131
	rem-long/2addr v9, v6
	xor-int/2addr v0, v11
	mul-float v70, v113, v44
	not-int v7, v11
	rsub-int v11, v11, -26961
	div-double v157, v15, v90
	sub-int v51, v234, v255
	const-wide v200, 524288L
	or-long v189, v189, v200
	div-long v169, v144, v189
	rsub-int v11, v2, 16124
	move-wide/from16 v0, v171
	xor-long/2addr v0, v9
	xor-int v98, v134, v243
	float-to-int v11, v14
	xor-int/2addr v2, v7
	div-double/2addr v15, v4
	rem-float/2addr v8, v14
	const-wide v171, 1073741824L
	or-long v0, v0, v171
	div-long/2addr v9, v0
	const-wide v171, 2L
	or-long v0, v0, v171
	div-long/2addr v9, v0
	const-wide v165, 65536L
	or-long v19, v19, v165
	rem-long v10, v146, v19
	sub-long/2addr v10, v0
	neg-float v4, v14
	div-float/2addr v14, v4
	double-to-long v8, v15
	ushr-long/2addr v0, v7
	neg-int v9, v2
	or-int/lit8 v2, v2, 13
	div-int/2addr v3, v2
	rsub-int v10, v2, -3427
	div-int/lit8 v145, v51, 14
	neg-float v1, v14
	rem-float/2addr v1, v14
	mul-long v9, v121, v55
	long-to-int v14, v9
	move-wide/from16 v4, v52
	add-long/2addr v9, v4
	mul-long/2addr v9, v4
	rem-int/lit8 v203, v51, 11
	int-to-float v8, v2
	const-wide v55, 16L
	or-long v9, v9, v55
	rem-long/2addr v4, v9
	or-int/lit8 v2, v2, 11
	rem-int/2addr v3, v2
	mul-int v233, v40, v69
	and-int/lit16 v10, v14, -6295
	mul-float/2addr v1, v8
	mul-long v148, v151, v146
	shl-int/lit8 v230, v142, -51
	shl-int v98, v119, v81
	or-int/2addr v10, v14
	shl-long v132, v220, v96
	neg-float v2, v8
	shr-long v154, v146, v103
	add-int/2addr v10, v7
	ushr-long/2addr v4, v14
	div-int/lit8 v227, v145, -86
	add-int/2addr v3, v7
	or-int/2addr v14, v3
	mul-int/lit8 v49, v21, 12
	add-int/2addr v3, v14
	mul-int/2addr v14, v7
	sub-float v225, v193, v194
	sub-float v99, v194, v2
	or-int/lit8 v31, v23, -87
	or-int/lit8 v177, v177, 86
	div-int v66, v63, v177
	int-to-float v12, v10
	move-wide/from16 v12, v154
	add-long/2addr v4, v12
	div-float/2addr v1, v8
	sub-int v218, v145, v94
	move-wide/from16 v8, v126
	div-double/2addr v8, v15
	long-to-double v8, v12
	mul-long/2addr v12, v4
	add-long/2addr v12, v4
	neg-int v1, v3
	neg-int v5, v7
	float-to-int v12, v2
	add-int v249, v145, v69
	rem-float v16, v178, v225
	move-wide/from16 v3, v114
	move-wide/from16 v3, v265
	move-wide/from16 v11, v121
	xor-long/2addr v11, v3
	rem-double v34, v29, v90
	shl-int/lit8 v162, v213, 36
	shl-int/lit8 v140, v145, 110
	ushr-int/lit8 v213, v46, 3
	double-to-float v12, v8
	invoke-static/range {v1}, LL/util;->print(I)V
	invoke-static/range {v2}, LL/util;->print(F)V
	invoke-static/range {v3 .. v4}, LL/util;->print(J)V
	invoke-static/range {v5}, LL/util;->print(I)V
	invoke-static/range {v7}, LL/util;->print(I)V
	invoke-static/range {v8 .. v9}, LL/util;->print(D)V
	invoke-static/range {v10}, LL/util;->print(I)V
	invoke-static/range {v12}, LL/util;->print(F)V
	invoke-static/range {v14}, LL/util;->print(I)V
	invoke-static/range {v16}, LL/util;->print(F)V
	invoke-static/range {v17 .. v18}, LL/util;->print(J)V
	invoke-static/range {v19 .. v20}, LL/util;->print(J)V
	invoke-static/range {v21}, LL/util;->print(I)V
	invoke-static/range {v22}, LL/util;->print(I)V
	invoke-static/range {v23}, LL/util;->print(I)V
	invoke-static/range {v24}, LL/util;->print(I)V
	invoke-static/range {v25}, LL/util;->print(F)V
	invoke-static/range {v26}, LL/util;->print(I)V
	invoke-static/range {v27}, LL/util;->print(I)V
	invoke-static/range {v28}, LL/util;->print(I)V
	invoke-static/range {v29 .. v30}, LL/util;->print(D)V
	invoke-static/range {v31}, LL/util;->print(I)V
	invoke-static/range {v34 .. v35}, LL/util;->print(D)V
	invoke-static/range {v38}, LL/util;->print(I)V
	invoke-static/range {v39}, LL/util;->print(F)V
	invoke-static/range {v40}, LL/util;->print(I)V
	invoke-static/range {v41}, LL/util;->print(I)V
	invoke-static/range {v42}, LL/util;->print(F)V
	invoke-static/range {v43}, LL/util;->print(I)V
	invoke-static/range {v44}, LL/util;->print(F)V
	invoke-static/range {v45}, LL/util;->print(I)V
	invoke-static/range {v46}, LL/util;->print(I)V
	invoke-static/range {v47 .. v48}, LL/util;->print(D)V
	invoke-static/range {v49}, LL/util;->print(I)V
	invoke-static/range {v51}, LL/util;->print(I)V
	invoke-static/range {v52 .. v53}, LL/util;->print(J)V
	invoke-static/range {v54}, LL/util;->print(I)V
	invoke-static/range {v55 .. v56}, LL/util;->print(J)V
	invoke-static/range {v58}, LL/util;->print(I)V
	invoke-static/range {v59}, LL/util;->print(I)V
	invoke-static/range {v60}, LL/util;->print(I)V
	invoke-static/range {v61 .. v62}, LL/util;->print(J)V
	invoke-static/range {v63}, LL/util;->print(I)V
	invoke-static/range {v64}, LL/util;->print(F)V
	invoke-static/range {v65}, LL/util;->print(I)V
	invoke-static/range {v66}, LL/util;->print(I)V
	invoke-static/range {v67}, LL/util;->print(I)V
	invoke-static/range {v69}, LL/util;->print(I)V
	invoke-static/range {v70}, LL/util;->print(F)V
	invoke-static/range {v73}, LL/util;->print(I)V
	invoke-static/range {v77}, LL/util;->print(I)V
	invoke-static/range {v78}, LL/util;->print(F)V
	invoke-static/range {v79}, LL/util;->print(I)V
	invoke-static/range {v81}, LL/util;->print(I)V
	invoke-static/range {v82}, LL/util;->print(I)V
	invoke-static/range {v83 .. v84}, LL/util;->print(J)V
	invoke-static/range {v85}, LL/util;->print(I)V
	invoke-static/range {v86}, LL/util;->print(I)V
	invoke-static/range {v89}, LL/util;->print(I)V
	invoke-static/range {v90 .. v91}, LL/util;->print(D)V
	invoke-static/range {v92}, LL/util;->print(I)V
	invoke-static/range {v93}, LL/util;->print(I)V
	invoke-static/range {v94}, LL/util;->print(I)V
	invoke-static/range {v96}, LL/util;->print(I)V
	invoke-static/range {v98}, LL/util;->print(I)V
	invoke-static/range {v99}, LL/util;->print(F)V
	invoke-static/range {v100}, LL/util;->print(F)V
	invoke-static/range {v101}, LL/util;->print(I)V
	invoke-static/range {v103}, LL/util;->print(I)V
	invoke-static/range {v104}, LL/util;->print(I)V
	invoke-static/range {v105}, LL/util;->print(F)V
	invoke-static/range {v106}, LL/util;->print(I)V
	invoke-static/range {v107}, LL/util;->print(I)V
	invoke-static/range {v109 .. v110}, LL/util;->print(D)V
	invoke-static/range {v111 .. v112}, LL/util;->print(J)V
	invoke-static/range {v113}, LL/util;->print(F)V
	invoke-static/range {v114 .. v115}, LL/util;->print(J)V
	invoke-static/range {v116}, LL/util;->print(F)V
	invoke-static/range {v117}, LL/util;->print(I)V
	invoke-static/range {v119}, LL/util;->print(I)V
	invoke-static/range {v120}, LL/util;->print(I)V
	invoke-static/range {v121 .. v122}, LL/util;->print(J)V
	invoke-static/range {v123}, LL/util;->print(I)V
	invoke-static/range {v124}, LL/util;->print(F)V
	invoke-static/range {v125}, LL/util;->print(F)V
	invoke-static/range {v126 .. v127}, LL/util;->print(D)V
	invoke-static/range {v128}, LL/util;->print(F)V
	invoke-static/range {v132 .. v133}, LL/util;->print(J)V
	invoke-static/range {v134}, LL/util;->print(I)V
	invoke-static/range {v135}, LL/util;->print(I)V
	invoke-static/range {v136}, LL/util;->print(I)V
	invoke-static/range {v137}, LL/util;->print(I)V
	invoke-static/range {v138 .. v139}, LL/util;->print(J)V
	invoke-static/range {v140}, LL/util;->print(I)V
	invoke-static/range {v142}, LL/util;->print(I)V
	invoke-static/range {v143}, LL/util;->print(I)V
	invoke-static/range {v145}, LL/util;->print(I)V
	invoke-static/range {v146 .. v147}, LL/util;->print(J)V
	invoke-static/range {v148 .. v149}, LL/util;->print(J)V
	invoke-static/range {v151 .. v152}, LL/util;->print(J)V
	invoke-static/range {v154 .. v155}, LL/util;->print(J)V
	invoke-static/range {v157 .. v158}, LL/util;->print(D)V
	invoke-static/range {v160}, LL/util;->print(I)V
	invoke-static/range {v162}, LL/util;->print(I)V
	invoke-static/range {v164}, LL/util;->print(I)V
	invoke-static/range {v165 .. v166}, LL/util;->print(J)V
	invoke-static/range {v167}, LL/util;->print(I)V
	invoke-static/range {v169 .. v170}, LL/util;->print(J)V
	invoke-static/range {v171 .. v172}, LL/util;->print(J)V
	invoke-static/range {v175 .. v176}, LL/util;->print(D)V
	invoke-static/range {v177}, LL/util;->print(I)V
	invoke-static/range {v178}, LL/util;->print(F)V
	invoke-static/range {v180}, LL/util;->print(I)V
	invoke-static/range {v181}, LL/util;->print(I)V
	invoke-static/range {v182}, LL/util;->print(F)V
	invoke-static/range {v183}, LL/util;->print(I)V
	invoke-static/range {v185}, LL/util;->print(F)V
	invoke-static/range {v189 .. v190}, LL/util;->print(J)V
	invoke-static/range {v191}, LL/util;->print(I)V
	invoke-static/range {v193}, LL/util;->print(F)V
	invoke-static/range {v194}, LL/util;->print(F)V
	invoke-static/range {v197 .. v198}, LL/util;->print(J)V
	invoke-static/range {v200 .. v201}, LL/util;->print(J)V
	invoke-static/range {v203}, LL/util;->print(I)V
	invoke-static/range {v205 .. v206}, LL/util;->print(D)V
	invoke-static/range {v207}, LL/util;->print(I)V
	invoke-static/range {v208}, LL/util;->print(I)V
	invoke-static/range {v210 .. v211}, LL/util;->print(J)V
	invoke-static/range {v212}, LL/util;->print(F)V
	invoke-static/range {v213}, LL/util;->print(I)V
	invoke-static/range {v215 .. v216}, LL/util;->print(D)V
	invoke-static/range {v217}, LL/util;->print(I)V
	invoke-static/range {v218}, LL/util;->print(I)V
	invoke-static/range {v219}, LL/util;->print(I)V
	invoke-static/range {v220 .. v221}, LL/util;->print(J)V
	invoke-static/range {v223}, LL/util;->print(I)V
	invoke-static/range {v225}, LL/util;->print(F)V
	invoke-static/range {v227}, LL/util;->print(I)V
	invoke-static/range {v229}, LL/util;->print(I)V
	invoke-static/range {v230}, LL/util;->print(I)V
	invoke-static/range {v232}, LL/util;->print(F)V
	invoke-static/range {v233}, LL/util;->print(I)V
	invoke-static/range {v234}, LL/util;->print(I)V
	invoke-static/range {v235}, LL/util;->print(F)V
	invoke-static/range {v236}, LL/util;->print(I)V
	invoke-static/range {v238 .. v239}, LL/util;->print(J)V
	invoke-static/range {v240}, LL/util;->print(I)V
	invoke-static/range {v241}, LL/util;->print(I)V
	invoke-static/range {v242}, LL/util;->print(F)V
	invoke-static/range {v243}, LL/util;->print(I)V
	invoke-static/range {v244}, LL/util;->print(I)V
	invoke-static/range {v245 .. v246}, LL/util;->print(D)V
	invoke-static/range {v247 .. v248}, LL/util;->print(J)V
	invoke-static/range {v249}, LL/util;->print(I)V
	invoke-static/range {v250}, LL/util;->print(I)V
	invoke-static/range {v252}, LL/util;->print(I)V
	invoke-static/range {v253 .. v254}, LL/util;->print(J)V
	invoke-static/range {v255}, LL/util;->print(I)V
	return-void
################################################################################
.end method


.method static testMathOpsSub2(IIIFFFJJJDDDJ)V
    .locals 257
################################################################################
	move/from16 v0, v257
	move/from16 v1, v258
	move/from16 v2, v259
	move/from16 v3, v260
	move/from16 v4, v261
	move/from16 v5, v262
	move-wide/from16 v6, v263
	move-wide/from16 v8, v265
	move-wide/from16 v10, v267
	move-wide/from16 v12, v269
	move-wide/from16 v14, v271
	move-wide/from16 v16, v273
	move/from16 v19, v5
	move/from16 v21, v2
	move-wide/from16 v23, v269
	move/from16 v25, v3
	move/from16 v27, v0
	move/from16 v29, v3
	move-wide/from16 v31, v267
	move/from16 v33, v3
	move/from16 v35, v261
	move-wide/from16 v37, v275
	move-wide/from16 v39, v271
	move/from16 v41, v1
	move/from16 v43, v3
	move-wide/from16 v45, v275
	move-wide/from16 v47, v45
	move-wide/from16 v49, v16
	move/from16 v51, v2
	move-wide/from16 v53, v23
	move-wide/from16 v55, v271
	move-wide/from16 v57, v37
	move-wide/from16 v59, v10
	move/from16 v61, v51
	move-wide/from16 v63, v59
	move-wide/from16 v65, v263
	move/from16 v67, v19
	move/from16 v69, v1
	move/from16 v71, v261
	move/from16 v73, v260
	move-wide/from16 v75, v14
	move-wide/from16 v77, v57
	move/from16 v79, v0
	move-wide/from16 v81, v63
	move/from16 v83, v69
	move/from16 v85, v3
	move/from16 v87, v259
	move-wide/from16 v89, v271
	move/from16 v91, v262
	move-wide/from16 v93, v57
	move-wide/from16 v95, v265
	move/from16 v97, v61
	move/from16 v99, v85
	move-wide/from16 v101, v12
	move/from16 v103, v41
	move-wide/from16 v105, v6
	move-wide/from16 v107, v275
	move-wide/from16 v109, v95
	move/from16 v111, v29
	move-wide/from16 v113, v47
	move/from16 v115, v258
	move-wide/from16 v117, v63
	move-wide/from16 v119, v53
	move/from16 v121, v25
	move/from16 v123, v111
	move/from16 v125, v257
	move-wide/from16 v127, v16
	move-wide/from16 v129, v45
	move-wide/from16 v131, v10
	move-wide/from16 v133, v119
	move/from16 v135, v19
	move/from16 v137, v51
	move-wide/from16 v139, v101
	move/from16 v141, v87
	move/from16 v143, v87
	move/from16 v145, v123
	move-wide/from16 v147, v119
	move-wide/from16 v149, v127
	move/from16 v151, v99
	move/from16 v153, v83
	move/from16 v155, v73
	move-wide/from16 v157, v10
	move/from16 v159, v67
	move/from16 v161, v115
	move/from16 v163, v29
	move-wide/from16 v165, v269
	move-wide/from16 v167, v267
	move/from16 v169, v111
	move/from16 v171, v161
	move-wide/from16 v173, v275
	move/from16 v175, v137
	move-wide/from16 v177, v93
	move-wide/from16 v179, v47
	move-wide/from16 v181, v109
	move/from16 v183, v1
	move-wide/from16 v185, v133
	move/from16 v187, v83
	move/from16 v189, v51
	move-wide/from16 v191, v75
	move/from16 v193, v21
	move-wide/from16 v195, v49
	move/from16 v197, v121
	move-wide/from16 v199, v113
	move-wide/from16 v201, v81
	move/from16 v203, v111
	move-wide/from16 v205, v105
	move-wide/from16 v207, v167
	move-wide/from16 v209, v93
	move/from16 v211, v29
	move-wide/from16 v213, v165
	move-wide/from16 v215, v107
	move-wide/from16 v217, v185
	move/from16 v219, v257
	move/from16 v221, v151
	move/from16 v223, v79
	move/from16 v225, v69
	move/from16 v227, v29
	move-wide/from16 v229, v177
	move/from16 v231, v99
	move/from16 v233, v159
	move/from16 v235, v193
	move-wide/from16 v237, v185
	move/from16 v239, v125
	move-wide/from16 v241, v23
	move-wide/from16 v243, v215
	move/from16 v245, v33
	move-wide/from16 v247, v133
	move/from16 v249, v4
	move-wide/from16 v251, v49
	move-wide/from16 v253, v117
	move-wide/from16 v255, v263
	rsub-int v7, v1, -5176
	xor-int v162, v1, v193
	float-to-double v11, v4
	not-int v13, v1
	sub-float/2addr v5, v3
	rsub-int v15, v0, 105
	or-long v13, v8, v57
	add-long/2addr v13, v8
	int-to-double v7, v1
	rem-double/2addr v11, v7
	rem-int/lit8 v46, v79, 91
	float-to-int v4, v3
	or-int/lit8 v187, v187, 86
	div-int v206, v175, v187
	const-wide v177, 131072L
	or-long v105, v105, v177
	div-long v49, v177, v105
	sub-double v135, v75, v139
	long-to-double v15, v13
	div-double/2addr v15, v11
	and-int v188, v46, v69
	mul-float v52, v99, v91
	long-to-double v4, v13
	shl-long/2addr v13, v1
	xor-int/lit8 v84, v189, 107
	shl-int/lit8 v161, v223, -21
	and-long v72, v255, v57
	shl-int/2addr v2, v0
	shr-int/lit8 v140, v21, 122
	not-long v9, v13
	rem-float v236, v151, v163
	xor-int/lit8 v62, v235, 65
	const-wide v63, 262144L
	or-long v9, v9, v63
	div-long/2addr v13, v9
	neg-double v8, v4
	float-to-int v2, v3
	const-wide v207, 256L
	or-long v59, v59, v207
	div-long v201, v113, v59
	const-wide v13, 536870912L
	or-long v173, v173, v13
	div-long v242, v117, v173
	ushr-int/lit8 v128, v46, -32
	rem-int/lit8 v176, v140, 73
	neg-long v10, v13
	shl-int/lit8 v44, v171, -40
	mul-double/2addr v15, v8
	xor-long/2addr v13, v10
	add-long v240, v253, v167
	mul-int/lit8 v68, v69, 47
	div-int/lit8 v188, v206, 15
	xor-long/2addr v13, v10
	long-to-float v7, v13
	and-long/2addr v13, v10
	sub-float v244, v159, v245
	mul-long v189, v117, v10
	not-long v2, v13
	ushr-int v147, v103, v84
	div-float v126, v163, v244
	and-int v217, v188, v84
	or-int/lit8 v223, v223, 2
	rem-int v12, v188, v223
	neg-int v6, v12
	const-wide v95, 4096L
	or-long v105, v105, v95
	rem-long v233, v199, v105
	rem-double v151, v213, v133
	and-int v240, v143, v223
	shl-int/2addr v1, v12
	div-float v185, v227, v7
	float-to-double v8, v7
	const v13, 0xf11e9925
	sub-float/2addr v13, v7
	and-int/lit16 v1, v0, 6753
	shl-long/2addr v2, v0
	shl-int v205, v147, v44
	sub-int/2addr v12, v6
	or-int/lit16 v12, v12, 10565
	shr-int v208, v162, v153
	long-to-float v11, v2
	xor-int/2addr v1, v0
	add-float v192, v169, v159
	sub-double/2addr v4, v8
	ushr-int/lit8 v21, v79, -10
	mul-int/2addr v12, v0
	int-to-byte v7, v12
	sub-int/2addr v7, v12
	shr-int v241, v21, v46
	rem-float/2addr v11, v13
	rem-int/lit8 v19, v0, 48
	sub-float v250, v111, v35
	or-int/2addr v6, v1
	long-to-float v6, v2
	shl-int v188, v115, v161
	rem-int/lit16 v8, v12, 6937
	and-int/lit16 v9, v12, -11803
	double-to-int v10, v4
	or-long v101, v215, v59
	sub-double v16, v213, v89
	mul-int v143, v83, v240
	add-float v126, v29, v99
	int-to-char v10, v0
	or-int/lit8 v183, v183, 29
	rem-int v182, v21, v183
	double-to-int v3, v4
	or-int/lit8 v70, v182, 4
	rem-float/2addr v6, v11
	int-to-byte v10, v9
	shl-int/2addr v1, v9
	or-int/lit8 v240, v240, 3
	div-int v63, v51, v240
	and-int/lit16 v3, v10, -14477
	mul-float v2, v221, v169
	or-int/lit8 v51, v51, 123
	div-int v177, v21, v51
	ushr-int/lit8 v135, v205, -15
	mul-int v33, v188, v61
	int-to-long v7, v3
	xor-int/2addr v10, v1
	int-to-short v8, v0
	or-int/lit8 v9, v9, 21
	div-int/2addr v3, v9
	sub-float/2addr v6, v2
	rem-double v7, v237, v195
	add-long v239, v72, v105
	const-wide v7, 0x1438f9ea71fe64b8L
	const-wide v4, 0x7fa17e6a03ef31afL
	or-long/2addr v7, v4
	long-to-int v11, v7
	const-wide v5, 0x8f04e9d7bcd4489bL
	neg-double v0, v5
	div-int/lit8 v185, v219, 127
	float-to-double v6, v2
	shl-int v36, v219, v140
	div-double v149, v237, v39
	const-wide v15, 0xffd1de2db1e5595cL
	long-to-double v4, v15
	xor-long v77, v77, v201
	rem-int/lit8 v140, v68, 119
	ushr-int/lit8 v59, v223, 80
	xor-int v15, v46, v103
	const-wide v1, 0x1d90d2c6c29f0faeL
	shr-long/2addr v1, v12
	ushr-long v143, v229, v9
	const-wide v6, 0x40b48cf0c6037700L
	const-wide v101, 67108864L
	or-long v1, v1, v101
	div-long/2addr v6, v1
	shr-int/lit8 v42, v12, -111
	or-long v189, v113, v253
	add-double v101, v119, v75
	and-long v194, v199, v72
	int-to-char v6, v11
	shr-long v112, v117, v208
	or-int/lit8 v6, v6, 62
	rem-int/2addr v10, v6
	neg-long v8, v1
	mul-int/2addr v12, v11
	mul-int/2addr v6, v15
	ushr-long v102, v179, v241
	add-int v53, v241, v61
	add-int/lit16 v4, v10, -30173
	ushr-long/2addr v8, v4
	const v5, 0x5779a673
	rem-float/2addr v5, v13
	float-to-long v10, v5
	and-int/2addr v6, v3
	neg-long v13, v1
	and-int/2addr v4, v12
	ushr-long v97, v167, v69
	const-wide v0, 0xf8cf255ed1cef466L
	const-wide v1, 0xaf797e450ea848fbL
	const-wide v1, 0x6bf1899fb38e2508L
	const-wide v13, 0x62ebb40d80290253L
	rem-double/2addr v13, v1
	neg-double v8, v13
	and-int/lit8 v221, v235, -64
	int-to-char v7, v3
	xor-int/2addr v3, v7
	or-int/lit8 v12, v12, 46
	div-int v101, v235, v12
	const-wide v2, 0xdfe35d6d41a2f73bL
	const-wide v95, 16L
	or-long v2, v2, v95
	div-long/2addr v10, v2
	and-int v55, v188, v187
	const-wide v233, 1024L
	or-long v10, v10, v233
	rem-long/2addr v2, v10
	mul-double/2addr v13, v8
	ushr-long/2addr v10, v4
	or-int/lit8 v135, v135, 31
	rem-int v98, v188, v135
	or-int/lit8 v12, v12, 1
	rem-int/2addr v6, v12
	shl-long v127, v253, v15
	xor-long/2addr v2, v10
	div-float v250, v71, v192
	or-int/lit8 v12, v12, 93
	div-int v229, v70, v12
	long-to-float v7, v10
	mul-double v114, v119, v165
	rem-float v89, v111, v52
	int-to-long v12, v15
	long-to-float v8, v12
	div-float/2addr v7, v8
	mul-float v160, v29, v35
	neg-float v10, v5
	shr-long v39, v253, v51
	long-to-int v11, v2
	and-int v207, v68, v188
	mul-double v105, v247, v114
	or-int/lit8 v10, v33, -31
	mul-long/2addr v12, v2
	const-wide v253, 4L
	or-long v12, v12, v253
	div-long/2addr v2, v12
	xor-int/lit8 v25, v217, -55
	mul-double v246, v133, v251
	shl-long/2addr v12, v11
	long-to-double v12, v2
	rem-float v97, v111, v121
	xor-int/lit8 v154, v140, 30
	shl-int/lit8 v225, v177, -74
	shl-long/2addr v2, v10
	add-int/2addr v11, v10
	const-wide v13, 0xf23b3c2fca9d3441L
	const-wide v11, 0x296a58bf30f0becL
	add-double/2addr v11, v13
	not-int v8, v4
	shl-long/2addr v2, v15
	shr-long/2addr v2, v8
	const-wide v107, 536870912L
	or-long v209, v209, v107
	rem-long v5, v112, v209
	add-int/2addr v4, v15
	xor-long/2addr v2, v5
	const-wide v31, 268435456L
	or-long v5, v5, v31
	div-long/2addr v2, v5
	int-to-byte v11, v10
	or-int v154, v70, v176
	xor-int/2addr v11, v15
	xor-int/2addr v11, v15
	sub-int v55, v177, v175
	sub-int/2addr v11, v15
	and-int/2addr v15, v10
	mul-int/lit8 v214, v125, 26
	rsub-int v15, v15, -31190
	xor-int/lit8 v49, v217, 71
	add-int/lit8 v237, v41, -7
	and-long v15, v5, v109
	int-to-long v6, v10
	xor-long v59, v253, v47
	ushr-int/lit8 v248, v161, -54
	div-double v37, v75, v149
	shl-int/lit8 v81, v8, 2
	xor-int/lit16 v7, v11, -4251
	double-to-long v11, v13
	sub-int/2addr v7, v10
	and-int/lit16 v7, v8, 19742
	and-long v79, v59, v2
	sub-int/2addr v7, v4
	long-to-double v11, v15
	int-to-float v8, v10
	add-long/2addr v2, v15
	div-double/2addr v11, v13
	xor-int/lit8 v137, v188, 66
	or-int/lit8 v7, v7, 107
	div-int/2addr v10, v7
	sub-double v215, v11, v149
	add-double v32, v37, v13
	int-to-float v15, v10
	shr-int/lit8 v84, v229, 7
	shl-int v183, v188, v83
	int-to-float v1, v7
	const-wide v1, 0x8adbad58ac0c4317L
	const-wide v2, 0x167bb72e54c7adbbL
	const-wide v6, 0x39b7e5f5dea20fceL
	and-long/2addr v2, v6
	const-wide v2, 8192L
	or-long v127, v127, v2
	div-long v182, v131, v127
	add-int/lit16 v8, v4, -8405
	add-int/lit16 v7, v8, 28478
	and-int/lit16 v9, v10, 21125
	shr-int/2addr v10, v8
	float-to-double v2, v15
	add-long v6, v93, v102
	const-wide v4, 0x607e77ab99113bb5L
	const-wide v157, 33554432L
	or-long v6, v6, v157
	div-long/2addr v4, v6
	neg-long v2, v6
	neg-double v4, v13
	add-int/2addr v8, v10
	or-int/lit8 v237, v237, 30
	div-int v236, v53, v237
	int-to-byte v14, v8
	div-double/2addr v11, v4
	or-int/lit8 v10, v10, 97
	div-int/2addr v14, v10
	mul-long/2addr v2, v6
	float-to-long v10, v15
	neg-int v9, v8
	or-int/lit8 v14, v14, 59
	div-int/2addr v9, v14
	or-int/lit8 v8, v8, 115
	div-int/2addr v9, v8
	and-int/lit16 v14, v14, -18604
	const-wide v7, 0x95bd82f27d5712fbL
	mul-double/2addr v4, v7
	ushr-long/2addr v10, v14
	const v11, 0x8fb96d9b
	mul-float/2addr v15, v11
	shr-int v147, v235, v53
	ushr-int/2addr v9, v14
	div-float v61, v245, v111
	mul-int/2addr v14, v9
	int-to-float v15, v9
	const-wide v15, 0xfb751b91cdaba70eL
	const-wide v167, 2097152L
	or-long v2, v2, v167
	rem-long/2addr v15, v2
	long-to-double v7, v15
	long-to-int v3, v2
	int-to-char v11, v14
	rem-double/2addr v7, v4
	and-long v160, v189, v157
	mul-long v39, v253, v107
	add-float v147, v163, v121
	sub-double v171, v165, v7
	shl-long v135, v93, v9
	shl-int/lit8 v182, v235, 55
	mul-double v18, v4, v251
	shl-int/lit8 v110, v214, -65
	rsub-int/lit8 v180, v140, -82
	move/from16 v13, v231
	float-to-int v5, v13
	and-int/2addr v9, v3
	or-int/lit8 v146, v3, 87
	shl-int/lit8 v64, v70, -28
	rem-int/lit8 v2, v44, -60
	const-wide v5, 0x8ad9485d849004ecL
	sub-double/2addr v7, v5
	sub-double v169, v165, v23
	sub-float v220, v227, v203
	not-int v4, v2
	int-to-long v8, v2
	or-int/2addr v3, v14
	rsub-int/lit8 v46, v2, -53
	shl-int/2addr v2, v3
	xor-int v65, v176, v193
	mul-long/2addr v15, v8
	double-to-int v11, v5
	const-wide v143, 268435456L
	or-long v15, v15, v143
	div-long/2addr v8, v15
	and-int v246, v101, v65
	and-long v104, v95, v239
	double-to-float v11, v5
	div-double v181, v171, v5
	mul-long/2addr v15, v8
	sub-long/2addr v15, v8
	rsub-int/lit8 v156, v125, 21
	double-to-int v10, v5
	and-int v168, v185, v193
	long-to-int v7, v15
	sub-int/2addr v14, v2
	add-double v43, v114, v133
	and-int v39, v101, v62
	shl-int/2addr v2, v3
	shl-int/lit8 v69, v110, 19
	not-long v8, v15
	ushr-long/2addr v8, v2
	and-long/2addr v15, v8
	shl-int v173, v141, v248
	xor-int/2addr v4, v2
	or-int/lit8 v10, v10, 39
	div-int/2addr v3, v10
	add-long/2addr v8, v15
	rsub-int v4, v7, -28889
	or-long/2addr v8, v15
	ushr-int/lit8 v17, v208, -46
	int-to-char v7, v10
	or-int/2addr v4, v7
	mul-int/lit8 v255, v4, 23
	add-float v59, v121, v91
	or-long/2addr v8, v15
	shl-long/2addr v8, v14
	mul-int/lit8 v106, v81, -62
	shl-int/lit8 v194, v180, 92
	and-int/lit8 v5, v110, 13
	rem-float v45, v155, v250
	shl-int/2addr v14, v5
	or-int/lit16 v11, v5, -5845
	const-wide v0, 0x5bc9a8c110a5c7d9L
	double-to-long v2, v0
	const-wide v143, 268435456L
	or-long v2, v2, v143
	div-long/2addr v8, v2
	int-to-char v5, v5
	div-int/lit8 v145, v63, -87
	or-int/lit8 v19, v214, -21
	or-int/lit8 v65, v65, 83
	div-int v109, v208, v65
	div-double v239, v171, v43
	add-int v48, v173, v219
	add-int v241, v219, v162
	add-double v33, v0, v75
	div-int/lit16 v9, v11, 2509
	const-wide v233, 1073741824L
	or-long v2, v2, v233
	rem-long/2addr v15, v2
	ushr-int v81, v140, v87
	mul-double v243, v33, v181
	shl-long/2addr v2, v9
	ushr-int v139, v154, v187
	mul-double v58, v149, v243
	or-int/lit8 v73, v98, 82
	move-wide/from16 v3, v269
	div-double/2addr v0, v3
	mul-int/2addr v11, v14
	ushr-int v177, v7, v10
	neg-long v0, v15
	ushr-long/2addr v15, v14
	shl-int v66, v84, v185
	add-long v123, v112, v93
	xor-int v113, v219, v141
	mul-long v11, v107, v104
	and-long/2addr v0, v15
	int-to-short v8, v7
	const-wide v6, 0x83d6ac584cac98f4L
	sub-double/2addr v3, v6
	or-int/lit8 v146, v146, 62
	div-int v19, v137, v146
	shr-int/2addr v5, v9
	const v7, 0xa778374e
	div-float/2addr v13, v7
	int-to-char v11, v14
	add-int v125, v205, v193
	neg-int v2, v11
	mul-int/2addr v8, v9
	add-float/2addr v7, v13
	xor-int v88, v146, v84
	not-long v8, v15
	double-to-int v8, v3
	neg-float v9, v13
	ushr-int v225, v187, v229
	add-double v114, v37, v171
	sub-int v121, v49, v137
	mul-float v106, v29, v211
	neg-long v6, v15
	add-float v155, v35, v9
	const-wide v8, 0xe5293897f4c25f94L
	mul-double/2addr v3, v8
	const v8, 0x68154576
	mul-float/2addr v8, v13
	add-float/2addr v13, v8
	const-wide v2, 0xeb3693acd6b84a0cL
	move-wide/from16 v4, v151
	sub-double/2addr v4, v2
	sub-long v198, v127, v104
	sub-long/2addr v0, v15
	xor-int/lit8 v131, v185, -7
	mul-int v157, v221, v180
	or-int/lit8 v11, v11, 125
	rem-int/2addr v14, v11
	add-double/2addr v4, v2
	or-long/2addr v6, v15
	add-int/lit8 v164, v83, -84
	add-double v0, v43, v151
	ushr-int/2addr v10, v14
	sub-int/2addr v11, v10
	rsub-int/lit8 v213, v49, -46
	sub-long v135, v198, v104
	div-double/2addr v4, v0
	add-float/2addr v13, v8
	add-long/2addr v15, v6
	shr-int/2addr v11, v10
	mul-int v159, v48, v217
	int-to-byte v12, v14
	xor-long/2addr v15, v6
	mul-int/lit8 v5, v188, -85
	or-long/2addr v15, v6
	add-float v223, v29, v111
	sub-int v208, v65, v180
	add-long/2addr v15, v6
	add-long/2addr v6, v15
	sub-int v172, v146, v131
	rem-float v170, v52, v91
	add-double v162, v239, v0
	float-to-double v2, v8
	or-int v146, v66, v153
	neg-long v9, v15
	const-wide v129, 1048576L
	or-long v127, v127, v129
	rem-long v1, v9, v127
	ushr-long/2addr v9, v14
	div-double v180, v43, v215
	or-long/2addr v15, v6
	add-int/lit8 v170, v42, -13
	shr-long/2addr v15, v12
	add-long v5, v107, v102
	add-long/2addr v15, v5
	add-int/2addr v11, v12
	shl-long v27, v107, v65
	mul-int/lit16 v5, v14, -15246
	invoke-static/range {v1 .. v2}, LL/util;->print(J)V
	invoke-static/range {v5}, LL/util;->print(I)V
	invoke-static/range {v8}, LL/util;->print(F)V
	invoke-static/range {v9 .. v10}, LL/util;->print(J)V
	invoke-static/range {v11}, LL/util;->print(I)V
	invoke-static/range {v12}, LL/util;->print(I)V
	invoke-static/range {v13}, LL/util;->print(F)V
	invoke-static/range {v14}, LL/util;->print(I)V
	invoke-static/range {v15 .. v16}, LL/util;->print(J)V
	invoke-static/range {v17}, LL/util;->print(I)V
	invoke-static/range {v19}, LL/util;->print(I)V
	invoke-static/range {v21}, LL/util;->print(I)V
	invoke-static/range {v23 .. v24}, LL/util;->print(D)V
	invoke-static/range {v25}, LL/util;->print(I)V
	invoke-static/range {v27 .. v28}, LL/util;->print(J)V
	invoke-static/range {v29}, LL/util;->print(F)V
	invoke-static/range {v33 .. v34}, LL/util;->print(D)V
	invoke-static/range {v35}, LL/util;->print(F)V
	invoke-static/range {v36}, LL/util;->print(I)V
	invoke-static/range {v37 .. v38}, LL/util;->print(D)V
	invoke-static/range {v39}, LL/util;->print(I)V
	invoke-static/range {v41}, LL/util;->print(I)V
	invoke-static/range {v42}, LL/util;->print(I)V
	invoke-static/range {v43 .. v44}, LL/util;->print(D)V
	invoke-static/range {v45}, LL/util;->print(F)V
	invoke-static/range {v46}, LL/util;->print(I)V
	invoke-static/range {v48}, LL/util;->print(I)V
	invoke-static/range {v49}, LL/util;->print(I)V
	invoke-static/range {v51}, LL/util;->print(I)V
	invoke-static/range {v52}, LL/util;->print(F)V
	invoke-static/range {v53}, LL/util;->print(I)V
	invoke-static/range {v55}, LL/util;->print(I)V
	invoke-static/range {v58 .. v59}, LL/util;->print(D)V
	invoke-static/range {v61}, LL/util;->print(F)V
	invoke-static/range {v62}, LL/util;->print(I)V
	invoke-static/range {v63}, LL/util;->print(I)V
	invoke-static/range {v64}, LL/util;->print(I)V
	invoke-static/range {v65}, LL/util;->print(I)V
	invoke-static/range {v66}, LL/util;->print(I)V
	invoke-static/range {v67}, LL/util;->print(F)V
	invoke-static/range {v68}, LL/util;->print(I)V
	invoke-static/range {v69}, LL/util;->print(I)V
	invoke-static/range {v70}, LL/util;->print(I)V
	invoke-static/range {v71}, LL/util;->print(F)V
	invoke-static/range {v73}, LL/util;->print(I)V
	invoke-static/range {v75 .. v76}, LL/util;->print(D)V
	invoke-static/range {v77 .. v78}, LL/util;->print(J)V
	invoke-static/range {v79 .. v80}, LL/util;->print(J)V
	invoke-static/range {v81}, LL/util;->print(I)V
	invoke-static/range {v83}, LL/util;->print(I)V
	invoke-static/range {v84}, LL/util;->print(I)V
	invoke-static/range {v85}, LL/util;->print(F)V
	invoke-static/range {v87}, LL/util;->print(I)V
	invoke-static/range {v88}, LL/util;->print(I)V
	invoke-static/range {v89}, LL/util;->print(F)V
	invoke-static/range {v91}, LL/util;->print(F)V
	invoke-static/range {v93 .. v94}, LL/util;->print(J)V
	invoke-static/range {v95 .. v96}, LL/util;->print(J)V
	invoke-static/range {v97}, LL/util;->print(F)V
	invoke-static/range {v98}, LL/util;->print(I)V
	invoke-static/range {v99}, LL/util;->print(F)V
	invoke-static/range {v101}, LL/util;->print(I)V
	invoke-static/range {v102 .. v103}, LL/util;->print(J)V
	invoke-static/range {v104 .. v105}, LL/util;->print(J)V
	invoke-static/range {v106}, LL/util;->print(F)V
	invoke-static/range {v107 .. v108}, LL/util;->print(J)V
	invoke-static/range {v109}, LL/util;->print(I)V
	invoke-static/range {v110}, LL/util;->print(I)V
	invoke-static/range {v111}, LL/util;->print(F)V
	invoke-static/range {v113}, LL/util;->print(I)V
	invoke-static/range {v114 .. v115}, LL/util;->print(D)V
	invoke-static/range {v117 .. v118}, LL/util;->print(J)V
	invoke-static/range {v119 .. v120}, LL/util;->print(D)V
	invoke-static/range {v121}, LL/util;->print(I)V
	invoke-static/range {v123 .. v124}, LL/util;->print(J)V
	invoke-static/range {v125}, LL/util;->print(I)V
	invoke-static/range {v126}, LL/util;->print(F)V
	invoke-static/range {v127 .. v128}, LL/util;->print(J)V
	invoke-static/range {v129 .. v130}, LL/util;->print(J)V
	invoke-static/range {v131}, LL/util;->print(I)V
	invoke-static/range {v133 .. v134}, LL/util;->print(D)V
	invoke-static/range {v135 .. v136}, LL/util;->print(J)V
	invoke-static/range {v137}, LL/util;->print(I)V
	invoke-static/range {v139}, LL/util;->print(I)V
	invoke-static/range {v140}, LL/util;->print(I)V
	invoke-static/range {v141}, LL/util;->print(I)V
	invoke-static/range {v143 .. v144}, LL/util;->print(J)V
	invoke-static/range {v145}, LL/util;->print(I)V
	invoke-static/range {v146}, LL/util;->print(I)V
	invoke-static/range {v147}, LL/util;->print(F)V
	invoke-static/range {v149 .. v150}, LL/util;->print(D)V
	invoke-static/range {v151 .. v152}, LL/util;->print(D)V
	invoke-static/range {v153}, LL/util;->print(I)V
	invoke-static/range {v154}, LL/util;->print(I)V
	invoke-static/range {v155}, LL/util;->print(F)V
	invoke-static/range {v156}, LL/util;->print(I)V
	invoke-static/range {v157}, LL/util;->print(I)V
	invoke-static/range {v159}, LL/util;->print(I)V
	invoke-static/range {v160 .. v161}, LL/util;->print(J)V
	invoke-static/range {v162 .. v163}, LL/util;->print(D)V
	invoke-static/range {v164}, LL/util;->print(I)V
	invoke-static/range {v165 .. v166}, LL/util;->print(D)V
	invoke-static/range {v168}, LL/util;->print(I)V
	invoke-static/range {v170}, LL/util;->print(I)V
	invoke-static/range {v172}, LL/util;->print(I)V
	invoke-static/range {v173}, LL/util;->print(I)V
	invoke-static/range {v175}, LL/util;->print(I)V
	invoke-static/range {v176}, LL/util;->print(I)V
	invoke-static/range {v177}, LL/util;->print(I)V
	invoke-static/range {v180 .. v181}, LL/util;->print(D)V
	invoke-static/range {v185}, LL/util;->print(I)V
	invoke-static/range {v187}, LL/util;->print(I)V
	invoke-static/range {v188}, LL/util;->print(I)V
	invoke-static/range {v189 .. v190}, LL/util;->print(J)V
	invoke-static/range {v192}, LL/util;->print(F)V
	invoke-static/range {v193}, LL/util;->print(I)V
	invoke-static/range {v194}, LL/util;->print(I)V
	invoke-static/range {v197}, LL/util;->print(F)V
	invoke-static/range {v198 .. v199}, LL/util;->print(J)V
	invoke-static/range {v201 .. v202}, LL/util;->print(J)V
	invoke-static/range {v203}, LL/util;->print(F)V
	invoke-static/range {v205}, LL/util;->print(I)V
	invoke-static/range {v206}, LL/util;->print(I)V
	invoke-static/range {v207}, LL/util;->print(I)V
	invoke-static/range {v208}, LL/util;->print(I)V
	invoke-static/range {v209 .. v210}, LL/util;->print(J)V
	invoke-static/range {v211}, LL/util;->print(F)V
	invoke-static/range {v213}, LL/util;->print(I)V
	invoke-static/range {v214}, LL/util;->print(I)V
	invoke-static/range {v215 .. v216}, LL/util;->print(D)V
	invoke-static/range {v217}, LL/util;->print(I)V
	invoke-static/range {v219}, LL/util;->print(I)V
	invoke-static/range {v220}, LL/util;->print(F)V
	invoke-static/range {v221}, LL/util;->print(I)V
	invoke-static/range {v223}, LL/util;->print(F)V
	invoke-static/range {v225}, LL/util;->print(I)V
	invoke-static/range {v227}, LL/util;->print(F)V
	invoke-static/range {v229}, LL/util;->print(I)V
	invoke-static/range {v231}, LL/util;->print(F)V
	invoke-static/range {v233 .. v234}, LL/util;->print(J)V
	invoke-static/range {v235}, LL/util;->print(I)V
	invoke-static/range {v236}, LL/util;->print(I)V
	invoke-static/range {v237}, LL/util;->print(I)V
	invoke-static/range {v239 .. v240}, LL/util;->print(D)V
	invoke-static/range {v241}, LL/util;->print(I)V
	invoke-static/range {v243 .. v244}, LL/util;->print(D)V
	invoke-static/range {v245}, LL/util;->print(F)V
	invoke-static/range {v246}, LL/util;->print(I)V
	invoke-static/range {v248}, LL/util;->print(I)V
	invoke-static/range {v249}, LL/util;->print(F)V
	invoke-static/range {v250}, LL/util;->print(F)V
	invoke-static/range {v251 .. v252}, LL/util;->print(D)V
	invoke-static/range {v253 .. v254}, LL/util;->print(J)V
	invoke-static/range {v255}, LL/util;->print(I)V
	return-void
################################################################################
.end method

.method static testMathOps()V
    .locals 71
    const-string v0, "testMathOps"
    invoke-static {v0}, LL/util;->print(Ljava/lang/String;)V

	const v0, 0x2B474BF7
	const v1, 0x14A58531
	const v2, 0x72A3E46D
	const v3, 0xB7BEE1D
	const v4, 0x651618D1
	const v5, 0x3D130D1C
	const-wide v6, 0x2CECF008F2BE4BD7L
	const-wide v8, 0x4E64550E594A49DFL
	const-wide v10, 0x7978EE668D7A0429L
	const-wide v12, 0x44884D0A131B5ED4L
	const-wide v14, 0x5D99F95670217C19L
	const-wide v16, 0x2812F2EE8A6C4DBL
	const-wide v18, 0x000000000000001L
 	invoke-static/range {v0..v19}, La/a;->testMathOpsSub(IIIFFFJJJDDDJ)V
 	invoke-static/range {v0..v19}, La/a;->testMathOpsSub2(IIIFFFJJJDDDJ)V

	const v0, 0xB16AEF39
	const v1, 0x9BCFEAE4
	const v2, 0xEE2666CA
	const v3, 0xAC87DEF8
	const v4, 0x7021D78D
	const v5, 0x2CA7A611
	const-wide v6, 0xEEC114876FBAB127L
	const-wide v8, 0xF00840148D88A4L
	const-wide v10, 0x1B8B994F7C805FEEL
	const-wide v12, 0xAAE2D6A105ECA0DEL
	const-wide v14, 0x20F2BCD3F7A8D5EEL
	const-wide v16, 0x82E1DA57B523421DL
	const-wide v18, 0x000000000000002L
	invoke-static/range {v0..v19}, La/a;->testMathOpsSub(IIIFFFJJJDDDJ)V
	invoke-static/range {v0..v19}, La/a;->testMathOpsSub2(IIIFFFJJJDDDJ)V

	return-void
.end method



.method public onCreate(Landroid/os/Bundle;)V
    .locals 12
    move-object/from16 v10, p0
    move-object/from16 v11, p1

    invoke-super {v10, v11}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    invoke-virtual {v10}, La/a;->testMoves()V
    invoke-static {v10}, La/a;->testCatchAll(L_;)V
    invoke-static {v10}, La/a;->testMonitor(L_;)V

    invoke-static {}, La/a;->testCasts()V
    invoke-static {}, La/a;->testImplicitCasts()V

    invoke-static {}, La/a;->testMathOps()V

    return-void
.end method
