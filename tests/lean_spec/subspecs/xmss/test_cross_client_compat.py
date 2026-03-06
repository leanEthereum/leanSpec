"""Cross-client XMSS signature compatibility tests."""

from __future__ import annotations

from typing import override

import pytest

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.subspecs.xmss.interface import PROD_SIGNATURE_SCHEME
from lean_spec.subspecs.xmss.types import HashDigestVector, Randomness
from lean_spec.types import Bytes32
from lean_spec.types.collections import SSZList
from lean_spec.types.container import Container

PROD_NODE_LIST_LIMIT = 1 << (PROD_CONFIG.LOG_LIFETIME // 2 + 1)


class ProdHashDigestList(SSZList[HashDigestVector]):
    """Hash digest list with prod-sized limit (works under any LEAN_ENV)."""

    LIMIT = PROD_NODE_LIST_LIMIT


class ProdHashTreeOpening(Container):
    """Merkle authentication path using prod-sized sibling list."""

    siblings: ProdHashDigestList


class ProdSignature(Container):
    """Signature container using prod-sized list limits for decoding."""

    path: ProdHashTreeOpening
    rho: Randomness
    hashes: ProdHashDigestList

    @classmethod
    @override
    def is_fixed_size(cls) -> bool:
        """Report as fixed-size, matching ream's `FixedBytes<3112>`."""
        return True

    @classmethod
    @override
    def get_byte_length(cls) -> int:
        """Return the prod signature byte length."""
        return PROD_CONFIG.SIGNATURE_LEN_BYTES


REAM_PUBLIC_KEY_HEX = (
    "7bbaf95bd653c827b5775e00b973b24d50ab4743db3373244f29c95fdf4ccc62"
    "8788ba2b5b9d635acdb25770e8ceef66bfdecd0a"
)

REAM_SIGNATURE_HEX = (
    "240000006590c5180f52a57ef4d12153ace9dd1bb346ea1299402d32978bd56f"
    "2804000004000000903b927d2ee9cf14087b2164dd418115962e322a6da10a58"
    "821ee20dd54f3c6a3f6dba14ebc2340b1aa7cc5647e08d0151024229312973331f"
    "669e1a268c8a2429d2353393f0d67a6b02da35e589da5bb099ea1ef931e9770c"
    "cae83a31f1454b359a4f4227fa1f17895918649115f3416bfa4e7976c5736170"
    "bc4e2acaf58342bf8e7472a2d6871e93bbbd01ebb6f30d51ccc3150e1d1e6c7b"
    "bfe15ea42cac218a8b94745184ce1f1098d62a9ea7a20662de0464f588225010"
    "84da7cbb58833ef9adfe59c17ac121676d92103a52903fbb70c1694717c46951"
    "40411977dfcb0e3da29612e27c590ef56967046817cb3727def54b4544f40314"
    "27be0a056ba7633334fd4104b0ba550521b61e16ecad72b5fda17de3e7a03bf6"
    "83f55ecefd215235c6481b5a6f873bc8134373f9fafc3053164e5f435c3d2ad7"
    "90221601ce274a4117f3104cadb00feb8baf79dd48904c5c1e0c1627c17c41ee"
    "7ca3760051ec163eee3e38a7bffa5779570a6cc078a630f5494f4917214954f1"
    "da636decff784335944a0674aa82096e5136063ef59c6962e95308074fed4bf6"
    "a81301d38a7919149bb24d221e5c44c12f82127c551413fef4f40b6f5ad646f4"
    "ca4578baf6f11d3325fe356168925b1f75690c17dbfd74d0d39756106c8a6d10"
    "c3bd355f27de621c72ca76734e523ebb8e647ef9fd216093f6bf086f075e4dcc"
    "607b5f6ff0603ca71787665a504621bdaf9e0b2924516972dc9c0ee1198f4ae3"
    "d6f7109c0c0f4b1708262685c7850709275e6e7f14cf4b74647a04005c501c37"
    "6d3a179014dc69d26716199b3811773d77800948ad6a6c620d1d2cd0d038283e"
    "10c659bd6c3635fa8634482cc14c1d476fa23a40f94d0dcb542b2230bb4f0283"
    "3713357b8f783b9ffaa50c32ef9933265a072bbc34b671800a8807fae7b235d3"
    "f2cc62804a4e3efecbb420122e6a6b62154976faff37329de17d7691a5213d54"
    "75b92132e48d657993d12c5eb5d0164f6af8589c199c1b61cf4619c60d723580"
    "97e43e5c5a676914748541e8d705626ac3654342f749361577056efe50e65e23"
    "2fd91c8588576db75cd96e004994278441bc2abac25a51cbdc095764bf7a64ff"
    "e05b06cea7bb446f6de72149bf850d795ddd15e464bf7377985f422e937e4ad0"
    "0563360340c93fd8d0c2695aaac71776f9476c4e574a7645285f5ca714cc021d"
    "88eb317d9c0177305bfa06f35622433447803322bf3833b617852b5cbd1d7abb"
    "ca563f124886792d0133298de40c6d4a8c802faa83da52211bdd5f13c1a14404"
    "16b40acc044774e083394d5e803a6a4a3123549d208c340448655b633d434784"
    "88717ebc9f3a09b514852c709cc77ace7bba083cc3826d3542ec663a55750838"
    "b83369521b40683a268413a302f90adb9a2954466d8d432b316021228f9763e7"
    "6e7a704866b66d0471626ae5f19c345147b64233266b7a58c7db0c246f370b91"
    "b490297ce07130166c424624d96b2adcb3a460fb0cce015f9e33194cc4a128f9"
    "153e1ddb24e1509e21793796b5b11fadc22218db97f3650ca8ec0e6003086fab"
    "38cf251b71ae2dece3716f3d50e26873ef8346c9951742953e0f720420af17b5"
    "30c1720f8f606e19a0c223d7059b6da670d12fd555313205312f7c151af068bb"
    "0b3d0f80333f2f73159e63a9c7cb46a88ede5ac4ddc20700bee377ec01f568cc"
    "179a6ccfc2e86d03912b779e2c4e5cc3d73d3b53f18001dee0032b276d456b82"
    "2d8b242d6d5e27b794ed14a2478e1c13eb5d0866990e4d75a27b1cca956737ca"
    "c4b16813ca29191720f632f9826e5cd2d32216a9580646bdcc1f0ff114e00661"
    "65f1368a324f27a97c3032a697f3317229782dfe053445921286144fbe7d7e68"
    "ac441a91c5cc2543ac6908cc171a67cdb0a638e19bb32f3dc6576b8b4aeb5aa4"
    "866a18a458972c1521345fbf885238afa6862b0ee4eb62b1c7b94026b8926f2f"
    "ae2f469b8bd02a6706995733b9321edaff6c429311f72ec541c65fccf9646f4e"
    "2ceb7c58d7f26e8280641dde221f0cb38cee6ccb9bd7238641fb11c576b02a2b"
    "47553858208a7ac9b6805a80474c38e3295d00f147ed3deb3d30503ec4076b25"
    "43bf307194b2787be3d53f3227ca3b815541709bbbc77a11eff92f5cccca7c76"
    "17e303c1b430799018aa0a94c7b152b154956a7e874507895e1735edc2683bb3"
    "28dd576ff11a2e3fc07f1ba086831e534dab1c0320920156155f72cc7e90795c"
    "268c2486d1dc4921204c53082dfb1b830bd9238794881c985ab247274990541c"
    "fa8f0e5e582e2caf44f7598f068272eb4ee81c5c04663504b745194c8c570169"
    "de83626063e20a6847b82c77931f321cd3ac5cbac802476969255a13a2fe6070"
    "7f960f5df8095c89cc786ffbe1b86a3e0b7f607f98982b9f10591c9c7bd14d21"
    "6bac36de88254da273a3601048cb47cb5c2954f34bae09d33d814162bf3d6da2"
    "de8c7a51331d437a8012420f6c1323b063e4085e32ee4d2864a14a66bffc29ef"
    "bca2328416901fe998be14033cb00b104d6732bdc8a963357b9d1290043229e3"
    "21c25f549c467415472e4061a30b616b23700cc930597e117438293330de628b"
    "7c465a8d79b150f0cf913a43e92e6c87e8e644412d0815c0086c46e3028b74d7"
    "967a6cf6f5332c4fea10320e90061dc0df4b3f01d0934772291c0cc9b8622b1e"
    "e9e120a0178613586b1370f71ef508bcc70c0728894621146a707a9c802321cc"
    "f7e50d5d4f8a21c5ced8480117bb11404cbc6eac8ec928507e912474c3fa4ba7"
    "dbd22781c28761d19e736f63e0c659c94f243b87271e2424505c2118c30c0dcf"
    "d7b719d2a6a549f28da317e1cbeb5748da595c86ada266aed25d18575368"
    "6e94914c68af6f4c5b833bd91033bbcb6b89cad52b9b65e110683dc96be38d69"
    "0780253c49bf454d783aa25c0838e00929155c943d7c80c83d0a22c65e6e49c7"
    "60f50b0623f074ee19138c08671cd6a846faf4237cbc4cee192106ed24545165"
    "2c591b5a04fd6537255f54a261f7df231fe13a803f617a4719ba15831c4fa848"
    "64f581772539091726fd0d3112a55781440796562a9324936110004039a3e3ec"
    "26078f76243e1be93df0166270055dcb65a94f2c14c5813145f4bd680c02c33e"
    "042d98d17e1c5a9c22d095ed30ad754144ae7f5150ac0df842d4e9415f849f1b"
    "36f2c1ff520be3d0721aab9b31c249df28aac8d9378326184262f53307bc77bc"
    "6ca59c3349bb29b90b7464ab666f563e5ac741a6390e6d634620fbb33182f958"
    "482746ff1138f53e55b9d1a119800e8d6fe04a46044781f813817514338a60a8"
    "044b3333249cc9c93cdf6c8537de140943f4907f7926f5a81ed20f1526fd9447"
    "412d81e75a05d93b7610e2e27d851b1163cb96e242c08796493f564e0e51a45e"
    "17e74b2619dafa0855922b714b84f1266bfc094e494c29175298d9a44eb5cf2d"
    "3a696c744f15a1f21d737fb45ed8af333157e88b1c89018d6322f91e751827c0"
    "30a6fb9d03554dee606a39cc6b79147906c18b376b1a39c20249a64c2b0b95e6"
    "26204ee24dcfa2665bd5ca0405df11391d15b8604130c3de32f7c43726c10bd5"
    "334b16df17f17456605008cb3cf926f0166209bc358562f32293073012bc7425"
    "0445e39e6cc14aa2613d77de1143e15c2e101cca14b9543d44b248a17c72279b"
    "743b0e18483a2331228bd57a3d5ecfa03f9318d269cbf992765ea15678046038"
    "749a04c35638c7984cbb90c40b7b94e657bc70a6760520fb4cbe1bbe62f5f7c1"
    "21268168361963cf3bf032f71e01d9555655faeb58e995c916d7b0850f681383"
    "0583717d36e9b4a319ccc4797386f072485834f4772d291a3976f1fa799ba0d0"
    "07822c011ad959895a4b29c11f3f9f07277a1ce94d1c5d9b0150a1e919528c17"
    "340031a204be28ff69ad90c13e4b81f354ef8ec11df62e9c62c1de715981bd4f"
    "4095a72d2eb68a5811bc059f0f58a5fa539a9a857e68604248d2fd5c28cabdf1"
    "1ae4a4692218a18d49d38ff76a6e2b8956b884ac0a5af9cc6680bfb62cf3d83a"
    "14d031f0404cc8930898bda055a934624650064e40665ce21754c72b6be81526"
    "62b5e29571be85b01cb7728045c92a5a37764a99062abb535c21260612b3026d"
    "1145be6c1b3d5e917ee457102fcfc8c5771d011d61f591271220a01e1dc11d1b"
    "441217577a5b5cc113421cd740bbe47556719bb51375eda8173d54706cafe98b"
    "6b9ad0f9639708e87e77fcbb2bb822ce59f0bdba7746ca286c5b98447d4ca2f0"
    "27b827ea4c7987e96a0429696bf9cfa21d6add9b79f2eddf2e6fe1c23c118ce2"
    "035ca0e3022270b628"
)

REAM_EPOCH = 5
REAM_MESSAGE = Bytes32(b"\x00" * 32)

ZEAM_PUBLIC_KEY_HEX = (
    "88119868a1228b6b710ece77f9064d5c9c90ba4e3be5a9246ab3086fc5863d57"
    "042575326f573f573016c520398daa7bea98d837"
)

ZEAM_SIGNATURE_HEX = (
    "2400000013abb160455288173880bb66b439784aaa87fa3e82048858ed545056"
    "2804000004000000117cc94e1a3b8c08b057451a7246e86d5e3fe92e12def85a"
    "aff7e127b315a22a7ce76405dda87f4b44b15a39edc78759d7e17b3334230907"
    "df8bca769709aa106b12672a2870f47c035be3598a64355250575f32e9ea881b"
    "9de1fa4d930bca74d919a63a350f5a1b14ebef5b06c2dc1d031abb4cc224436b"
    "559c501d9e6f2c47be269772a0f05f77d7fd251bb1013d14bb8dcd64e98a1d0"
    "52524f913e713c500c9d67f4914bcd879c073d60c5fc0f36e4dae7e0d4883294"
    "25c2e8f354bcc2c72cb2d863fb7ef26257260e64a479d5e31902a373f2e6d613"
    "e4c2640403eb13407cb27872896f5931d367e6e5695e27102fde00a56b28c4c0"
    "df38a2c34d4dd383a58a96a3607ed3071f832e24d8b711625da8a7a7eda213e5"
    "970ee5121834a57434114724725b3e34621157c33b717d307f789b414e1b8585"
    "0b9e4e422a6f70f0482a011210185e54e0b1b9e6ab987147c3cbe6a022e3d965"
    "152fa3238aa1ac67454c40d4af450c145d65e37211c49e8529348f41e43baaa3"
    "0b426086881d1e442794c8624f6275a39faf3402895d96801d315112e7ef9f34"
    "b018c135dfa70f62d32049a6052c3315bf706495b53386479c042dd304a80184"
    "aea07e7185acd811ab961e02beb9067633b3d8749b94d052437d2ed3f3f046e2"
    "683ea2c52b9e84d576fd1114a6a06254a7f741634f25b0b33e7d264053979af6"
    "ad9310b5aad0cac2a325c88739fc54a703343b073e216fb0e1e68ed59b107b06"
    "aeebbe75ff80869238323ae60a30154194dfd7e55a196a854d1955533a07b4e0"
    "3e9b52b7e6cadd8706dcde83fafc13b64a3b7762269fea336a58f9a48608c966"
    "41cf6e536cb91af55ada33011b8d594516e1405117ec35a17e19e1741843d7f3"
    "4d2810f4b270d3177f72ca51e5b44e822b966260375686505d359f92aac91cd2"
    "7c707764f9eff0e57f897c20615af84457a25c629a8f12a2a420f0335902e0f6"
    "393f27c1536bcb87c8cbb273530add32fbab7ea5cdb992676d3ea6c7e86f1df4"
    "ff4ceae6ed2892f52717a431e712e2c4df5201d41f43bb128632d8c48d1b4737"
    "0c50bf9332937be7a162fe7540cf2c846dc7de876d751f9428caf4d34e1c6530"
    "59b6eca646414905780d0e0031fa7e43b094eed4ae4131a33d94dca39f5324a1"
    "0d2e7412a8aecc01b9a6c6d334ad1f34f401f3440b92fb60f2821f81b8a192a5"
    "df4ac9c01ac51570fc474c91c320cbe66e663f21fff66a2427dc050655c74f36"
    "a4d5b423251aea456635e9c73bd49826fd553a6544439b46390ec1012ab748d0"
    "bcd82be138af0670eaeb3ca0cb484033e0070da124dacd61c5efb746f238ff63"
    "268bd7251cd624c2f021d0924fd7f18545211495612f49e42d8e0b249132bf13"
    "37b84ea0f8f9af378e79f3c2d1a28180ecf30e12d4aedfa4e95bdb629de28d34"
    "45b0cfb028a710a741d3fd67457056860e3e8c932d23ae828f939f32527690a1"
    "bb0e2ff2fd333aa4a80679f3261a4fc3f19afe040046aae4a23edb363eb0f1e6"
    "eeaafc936a5fc185ea6eb62741e2cf3460ba1ad32c070de428a519a49ff8eec2"
    "24abf9a489bdf1271a4460919143ac6549ce67b7a6edcb374b7563a00a111e84"
    "350f8754b8f1cf110b91ab16a6e485d4d47313357923bae4c559e700ad09b7b3"
    "baba4f40f95dfa82c57fb555cd2336165ad2a8866d9c7c429f4cf395cc1b5da6"
    "b6d752640f2c0947a11aa3a4d353d480d54bf5428277c6c18748a640cdb2b735"
    "46ab50c326db23e51092a7d3cd2c6a90517738d31bef36b2a4d36a75a575f374"
    "afdf32f5222a16e0372413e18a7ef3d39795c1d59dac8842314975b5c9f2fdc6"
    "10fe5bd011d8a833f75e7ef32d75b236559806b631fb03c676c71de78cac5b32"
    "f704e9a2421429765a1e4f062b681c90466001c0db689e334e9e06e69b37e335"
    "53658e61517b9372c9537092826d83907c7fb72106840de5a96fbf769d8bf8f6"
    "ca839432891a1802bf1b9e917ae674641e0959631aec0dd04c7404e4c3278480"
    "f361aec15af575240ce0951627b761209816040105d058364601b4458a8f82a5"
    "032a38c4fe043066b61bbd5301e0e366e83b319232e85283b47d8db3a272c7a7"
    "03384ec2cee851510b7eda437b66eef2192de155ac239866b43c4415a89141e7"
    "821a94d60a7f8806b48f5dd3694b782325079fa1ba68c1d340fc1c73450aa162"
    "6222f191a1a417a4c16b184410917a01d9d93a05ce926173cda9a8e2af8c2e11"
    "ad7031e5084341b3f2e43c01a7601347a5d80167dfa184b4e20d5db146e00ae0"
    "f22c4e53808f78b5aa1411b0e396d993766536b097d737a321fb3ad3c035ed62"
    "013ec673f2c4e0c7c6994407e16de9b445c818a57595bd64784219703db57616"
    "4d2ad116cca3f2734a0ddf51bf68cce7cfd4c0745c3e2147b7d684d28374a0a3"
    "bc2b0e723c06e263a28711b5f1ad36251abcb774b6223f47190e4b3203891ec1"
    "fb57c7d2b67d22e1ff72c6a2b377fe5115ff9eb1a61f88521c1b74575d3dda30"
    "8f304373a274d57641dcb9c3c325ae9578a1d3b582357a719dc7c74235a89d07"
    "ce82eea1e43bf7d269847657e71bc072b01bf36692d610608996ddb21fa0b0f7"
    "49cc52f31318e741cbafc520d79385a049404646d7a53bf411783214ec62da95"
    "3094187310e742b7a87cf0e04c50c34304d920767cff314436747d663fee0516"
    "b65d6b6460e682965d2ab34096f5ce50fab2ab1518220973873eac403a570496"
    "3d6758f07e11382273b53690d7e632e72cb4a457852bbab55dc5d035d7e8a9f3"
    "4649e10493d4d2d60efd3484b09acba40dc72b23c4c59ca759b6b3a29cb250a5"
    "754c28a79f4c413303ee0ad10aa03086dd4cd5e3d13cccf3d41517c7cdaeacc6"
    "b88038b3714839f104051c3238189612ecd94b0230f4f6758b1f41b02d191f80"
    "bd93db84789c92d2f73252f4e5b068a3b2bc8c65d4eb94b442784773540f40f4"
    "67d033235c526166bff17941c93e95e2afc2b37005035ea03d9456f4d952e052"
    "c3504a805009842524cb5cd035c2b2f12b1e24764de13f70db3f97b4e71f4de3"
    "5b86fcf04e997c657baf32b4b4478521b61a8d200bb02f0792556af0f5516b11"
    "ef8eb4d744413e07efed491758a8cb359d54934538d0acb4096f3795e4cecd11"
    "b849be92710df224282e2832c5494dc1e7bdc5476376557376c493020e0c6b30"
    "000fe7f0733a99e126036cd3672efda1ae05773288e04dd48c6e4164e5d64936"
    "009960e134cb38b0c4033406d7580ea0bb38d3443b644b416743a7c69648ede6"
    "06f93042d9601d568da767d20f4d9ca5363f19f1e3ddb1c3cfbeb5f3ba8bdad5"
    "85e725d54510ea85038e2322c33dfc6674d5f4d06f980086ccf719023f56c2d7"
    "18e649c014a16283d4cc45d0b0ec59b7a38397c76ebed2559a9d98b6504f70c5"
    "385b94a1e48b1a311b8842d66cc4cc850cf87c02f07d981414db0f204777fe37"
    "0705b2872ec83e935ec403c71e708570733277e4ee2e6366ee41d6d749577590"
    "09f24dd5775123a0a8829ab36d193897e6dbda05dfe76966bfd28c52a69ab8f1"
    "340785d3cc971d116e34184797e15746bf4b8bc0b0ed5240f12c820004d3c254"
    "91c514a6c5fbbbb2ca390020a60708e1fc31ef369de3f083e3f6b9968fffb064"
    "3f536e1330f371e481d44ef32c43ee73b13f908771c328c5ce71bd32859e0805"
    "1d5727657156dda123b20e0270b443d359183a675eaf5f065468b3a60be2a137"
    "8f3b3cb58175efc05934aa65322cffb30f2291f125239d8742e4f781b4638f65"
    "c4eac24706be8bb6e542b1b0d70db5563280ebe77b3e1146503e22b28a8056a4"
    "c5e0100073e6c9223237e0d16eb5175154b9557746cc3bd006639a9666519cd4"
    "19bab55344b1907194556b2453e195e3d8ce0a038f4cdba5ddd8c44567a5dca4"
    "69dcc0e4baaf3f3231d5912014991f328cb2b872be9ed197ea032c76c25c7e10"
    "43238376b03c1d23151a82a29a8b71e5c2d715c0adfa300396720fe7ceef8254"
    "e3f5a535b50331d31bc550f130958ad1ba1d0823ea357d72624692c027536e00"
    "59a642c06bc47ca7c34d3776cf577ba42bff18e7ac5bb7a0898fa573da5e9e53"
    "79c3d5c3f2b49f71afb0e79517b718c3ff87c5475a33e086c7e3ee05d6138977"
    "0a21b5f3e768d8404c565150456b2a808bef5c56878bf757824814e7066b3037"
    "5421e22359ce7cf23a688c2499081805f821a0561215ab62e5b38f51d3b4cd41"
    "956efa112d03db865afd8f510cd155e01ee54746d4f0ee0325854cb524f17826"
    "89948a071403f7a44f6d0493a27f3751a426a714335452b2cc131f54254a5673"
    "b772f9f7d5e2dc418"
)

ZEAM_EPOCH = 10
ZEAM_MESSAGE = Bytes32(b"\x01" + b"\x00" * 31)


@pytest.fixture()
def ream_public_key() -> PublicKey:
    """Decode the ream-generated public key from raw SSZ bytes."""
    return PublicKey.decode_bytes(bytes.fromhex(REAM_PUBLIC_KEY_HEX))


@pytest.fixture()
def ream_signature() -> ProdSignature:
    """Decode the ream-generated signature from raw SSZ bytes."""
    return ProdSignature.decode_bytes(bytes.fromhex(REAM_SIGNATURE_HEX))


@pytest.fixture()
def zeam_public_key() -> PublicKey:
    """Decode the zeam-generated public key from raw SSZ bytes."""
    return PublicKey.decode_bytes(bytes.fromhex(ZEAM_PUBLIC_KEY_HEX))


@pytest.fixture()
def zeam_signature() -> ProdSignature:
    """Decode the zeam-generated signature from raw SSZ bytes."""
    return ProdSignature.decode_bytes(bytes.fromhex(ZEAM_SIGNATURE_HEX))


class TestReamCrossClientCompat:
    """Verify ream-produced XMSS artifacts decode and verify in leanSpec."""

    def test_decode_public_key(self, ream_public_key: PublicKey) -> None:
        """SSZ decode + re-encode roundtrip for the public key."""
        raw = bytes.fromhex(REAM_PUBLIC_KEY_HEX)
        assert len(raw) == PROD_CONFIG.PUBLIC_KEY_LEN_BYTES
        assert ream_public_key.encode_bytes() == raw

    def test_decode_signature(self, ream_signature: ProdSignature) -> None:
        """SSZ decode + re-encode roundtrip for the signature."""
        raw = bytes.fromhex(REAM_SIGNATURE_HEX)
        assert len(raw) == PROD_CONFIG.SIGNATURE_LEN_BYTES
        assert ream_signature.encode_bytes() == raw

    def test_verify_signature(
        self, ream_public_key: PublicKey, ream_signature: ProdSignature
    ) -> None:
        """Full XMSS verification of a ream-produced signature."""
        assert PROD_SIGNATURE_SCHEME.verify(
            ream_public_key,
            Slot(REAM_EPOCH),
            REAM_MESSAGE,
            ream_signature,  # type: ignore[arg-type]
        )

    def test_rejects_wrong_message(
        self, ream_public_key: PublicKey, ream_signature: ProdSignature
    ) -> None:
        """Signature must not verify against a different message."""
        wrong_message = Bytes32(b"\xff" * 32)
        assert not PROD_SIGNATURE_SCHEME.verify(
            ream_public_key,
            Slot(REAM_EPOCH),
            wrong_message,
            ream_signature,  # type: ignore[arg-type]
        )

    def test_rejects_wrong_slot(
        self, ream_public_key: PublicKey, ream_signature: ProdSignature
    ) -> None:
        """Signature must not verify for a different slot."""
        wrong_slot = Slot(REAM_EPOCH + 1)
        assert not PROD_SIGNATURE_SCHEME.verify(
            ream_public_key,
            wrong_slot,
            REAM_MESSAGE,
            ream_signature,  # type: ignore[arg-type]
        )


class TestZeamCrossClientCompat:
    """Verify zeam-produced XMSS artifacts decode and verify in leanSpec."""

    def test_decode_public_key(self, zeam_public_key: PublicKey) -> None:
        """SSZ decode + re-encode roundtrip for the public key."""
        raw = bytes.fromhex(ZEAM_PUBLIC_KEY_HEX)
        assert len(raw) == PROD_CONFIG.PUBLIC_KEY_LEN_BYTES
        assert zeam_public_key.encode_bytes() == raw

    def test_decode_signature(self, zeam_signature: ProdSignature) -> None:
        """SSZ decode + re-encode roundtrip for the signature."""
        raw = bytes.fromhex(ZEAM_SIGNATURE_HEX)
        assert len(raw) == PROD_CONFIG.SIGNATURE_LEN_BYTES
        assert zeam_signature.encode_bytes() == raw

    def test_verify_signature(
        self, zeam_public_key: PublicKey, zeam_signature: ProdSignature
    ) -> None:
        """Full XMSS verification of a zeam-produced signature."""
        assert PROD_SIGNATURE_SCHEME.verify(
            zeam_public_key,
            Slot(ZEAM_EPOCH),
            ZEAM_MESSAGE,
            zeam_signature,  # type: ignore[arg-type]
        )

    def test_rejects_wrong_message(
        self, zeam_public_key: PublicKey, zeam_signature: ProdSignature
    ) -> None:
        """Signature must not verify against a different message."""
        wrong_message = Bytes32(b"\xff" * 32)
        assert not PROD_SIGNATURE_SCHEME.verify(
            zeam_public_key,
            Slot(ZEAM_EPOCH),
            wrong_message,
            zeam_signature,  # type: ignore[arg-type]
        )

    def test_rejects_wrong_slot(
        self, zeam_public_key: PublicKey, zeam_signature: ProdSignature
    ) -> None:
        """Signature must not verify for a different slot."""
        wrong_slot = Slot(ZEAM_EPOCH + 1)
        assert not PROD_SIGNATURE_SCHEME.verify(
            zeam_public_key,
            wrong_slot,
            ZEAM_MESSAGE,
            zeam_signature,  # type: ignore[arg-type]
        )
