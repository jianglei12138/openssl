LOCAL_PATH := $(call my-dir)

####################################################libcrypto#######################################################

include $(CLEAR_VARS)
LOCAL_MODULE    := libcrypto
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/crypto/include \
	$(LOCAL_PATH)/include/internal \
	$(LOCAL_PATH)/include/openssl \
	$(LOCAL_PATH)/include/ \
	$(LOCAL_PATH)/crypto/ \

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \
	-DOPENSSL_THREADS \
	-DOPENSSL_NO_DYNAMIC_ENGINE \
	-DOPENSSL_PIC -DOPENSSL_BN_ASM_MONT \
	-DOPENSSL_BN_ASM_GF2m \
	-DSHA1_ASM \
	-DSHA256_ASM \
	-DSHA512_ASM \
	-DAES_ASM \
	-DBSAES_ASM \
	-DGHASH_ASM \
	-DECP_NISTZ256_ASM \
	-DPOLY1305_ASM  \
	-mandroid -fPIC   \
    -DOPENSSL_NO_ASYNC
LOCAL_ASM_FILES := \
	crypto/aes/asm/aes-armv4.S \
	crypto/aes/asm/bsaes-armv7.S \
	crypto/aes/asm/aesv8-armx.S \
	crypto/bn/asm/armv4-gf2m.S \
	crypto/bn/asm/armv4-mont.S \
	crypto/armv4cpuid.S \
	crypto/chacha/asm/chacha-armv4.S \
	crypto/ec/asm/ecp_nistz256-armv4.S \
	crypto/modes/asm/ghash-armv4.S \
	crypto/modes/asm/ghashv8-armx.S \
	crypto/poly1305/asm/poly1305-armv4.S \
	crypto/sha/asm/sha1-armv4-large.S \
	crypto/sha/asm/sha256-armv4.S \
	crypto/sha/asm/sha512-armv4.S

LOCAL_SRC_FILES := \
	crypto/objects/o_names.c   crypto/pkcs7/pk7_lib.c     crypto/pkcs7/pk7_asn1.c    crypto/sha/sha256.c             \
	crypto/objects/obj_dat.c   crypto/pkcs7/pk7_mime.c    crypto/srp/srp_lib.c       crypto/idea/i_cbc.c             \
	crypto/objects/obj_err.c   crypto/pkcs7/pk7_smime.c   crypto/srp/srp_vfy.c       crypto/idea/i_cfb64.c           \
	crypto/objects/obj_lib.c   crypto/pkcs7/pkcs7err.c    crypto/stack/stack.c       crypto/idea/i_ecb.c             \
	crypto/objects/obj_xref.c  crypto/des/str2key.c       crypto/idea/i_ofb64.c      crypto/o_init.c                 \
	crypto/idea/i_skey.c       crypto/seed/seed.c         crypto/ts/ts_req_utils.c   crypto/ts/ts_verify_ctx.c       \
	crypto/seed/seed_cbc.c     crypto/ts/ts_asn1.c        crypto/ts/ts_rsp_print.c   crypto/whrlpool/wp_block.c      \
	crypto/seed/seed_cfb.c     crypto/ts/ts_conf.c        crypto/ts/ts_rsp_sign.c    crypto/whrlpool/wp_dgst.c       \
	crypto/seed/seed_ecb.c     crypto/ts/ts_lib.c         crypto/ts/ts_rsp_utils.c   crypto/camellia/camellia.c      \
	crypto/seed/seed_ofb.c     crypto/ts/ts_req_print.c   crypto/armcap.c  			 crypto/sha/sha1dgst.c           \
	crypto/asn1/a_bitstr.c     crypto/asn1/a_utf8.c       crypto/o_fips.c            crypto/pkcs12/pk12err.c         \
	crypto/asn1/a_d2i_fp.c     crypto/asn1/a_digest.c     crypto/asn1/a_dup.c        crypto/asn1/a_verify.c          \
	crypto/asn1/a_gentm.c      crypto/asn1/a_i2d_fp.c     crypto/aes/aes_cbc.c       crypto/o_dir.c                  \
	crypto/asn1/a_int.c        crypto/asn1/a_mbstr.c      crypto/asn1/a_object.c     crypto/aes/aes_cfb.c            \
	crypto/asn1/a_octet.c      crypto/asn1/a_print.c      crypto/asn1/n_pkey.c       crypto/async/arch/async_posix.c \
	crypto/asn1/a_sign.c       crypto/asn1/a_strex.c      crypto/asn1/a_strnid.c     crypto/asn1/nsseq.c             \
	crypto/asn1/a_time.c       crypto/asn1/a_type.c       crypto/asn1/a_utctm.c      crypto/aes/aes_ecb.c            \
	crypto/aes/aes_ige.c       crypto/aes/aes_misc.c      crypto/aes/aes_ofb.c       crypto/aes/aes_wrap.c           \
	crypto/asn1/ameth_lib.c    crypto/asn1/asn_mime.c     crypto/asn1/asn_moid.c     crypto/asn1/asn_pack.c          \
	crypto/asn1/asn1_err.c     crypto/asn1/asn1_gen.c     crypto/asn1/asn1_lib.c     crypto/asn1/asn1_par.c          \
	crypto/bio/b_dump.c        crypto/bio/b_print.c       crypto/bio/b_sock.c        crypto/bf/bf_cfb64.c            \
	crypto/bf/bf_ecb.c         crypto/bf/bf_enc.c         crypto/bf/bf_ofb64.c       crypto/bio/bf_null.c            \
	crypto/bf/bf_skey.c        crypto/bio/bf_buff.c       crypto/bio/bf_nbio.c       crypto/bio/bio_lib.c            \
	crypto/bio/bio_cb.c        crypto/bio/bio_err.c       crypto/evp/bio_ok.c        crypto/pkcs7/bio_pk7.c          \
	crypto/asn1/bio_asn1.c     crypto/asn1/bio_ndef.c     crypto/evp/bio_b64.c       crypto/evp/bio_enc.c            \
	crypto/evp/bio_md.c        crypto/bn/bn_add.c         crypto/bn/bn_asm.c         crypto/bn/bn_blind.c            \
	crypto/bn/bn_const.c       crypto/bn/bn_ctx.c         crypto/bn/bn_div.c         crypto/bn/bn_depr.c             \
	crypto/bn/bn_err.c         crypto/bn/bn_exp.c         crypto/bn/bn_exp2.c        crypto/bn/bn_gcd.c              \
	crypto/bn/bn_gf2m.c        crypto/bn/bn_kron.c        crypto/bn/bn_lib.c         crypto/bn/bn_mod.c              \
	crypto/bn/bn_mont.c        crypto/bn/bn_print.c       crypto/bn/bn_sqrt.c        crypto/bio/bss_conn.c           \
	crypto/bn/bn_mpi.c         crypto/bn/bn_rand.c        crypto/bn/bn_word.c        crypto/bio/bss_dgram.c          \
	crypto/bn/bn_mul.c         crypto/bn/bn_recp.c        crypto/bn/bn_x931p.c       crypto/bio/bss_fd.c             \
	crypto/bn/bn_nist.c        crypto/bn/bn_shift.c       crypto/bio/bss_acpt.c      crypto/bio/bss_file.c           \
	crypto/bn/bn_prime.c       crypto/bn/bn_sqr.c         crypto/bio/bss_bio.c       crypto/bio/bss_log.c            \
	crypto/bio/bss_mem.c       crypto/asn1/x_long.c       crypto/x509/x_x509a.c      crypto/cast/c_ecb.c             \
	crypto/bio/bss_null.c      crypto/x509/x_name.c       crypto/buffer/buf_err.c    crypto/cast/c_enc.c             \
	crypto/bio/bss_sock.c      crypto/cast/c_ofb64.c      crypto/pkcs12/p12_p8d.c    crypto/rsa/rsa_x931.c           \
	crypto/asn1/x_algor.c      crypto/asn1/x_pkey.c       crypto/buffer/buffer.c     crypto/cast/c_skey.c            \
	crypto/x509/x_all.c        crypto/asn1/x_pubkey.c     crypto/x509/by_dir.c       crypto/pkcs12/p12_key.c         \
	crypto/x509/x_attrib.c     crypto/x509/x_req.c        crypto/x509/by_file.c      crypto/comp/c_zlib.c            \
	crypto/asn1/x_bignum.c     crypto/asn1/x_sig.c        crypto/x509/x509_cmp.c     crypto/pkcs12/p12_init.c        \
	crypto/x509/x_crl.c        crypto/asn1/x_spki.c       crypto/evp/c_allc.c        crypto/des/cbc_cksm.c           \
	crypto/x509/x_exten.c      crypto/asn1/x_val.c        crypto/evp/c_alld.c        crypto/des/cbc_enc.c            \
	crypto/asn1/x_info.c       crypto/x509/x_x509.c       crypto/cast/c_cfb64.c      crypto/x509/x509_att.c          \
	crypto/x509/x509_d2.c      crypto/x509v3/v3_akey.c    crypto/x509v3/v3_pcons.c   crypto/cms/cms_lib.c            \
	crypto/x509/x509_def.c     crypto/x509v3/v3_akeya.c   crypto/x509v3/v3_pku.c     crypto/cms/cms_pwri.c           \
	crypto/x509/x509_err.c     crypto/x509v3/v3_alt.c     crypto/x509v3/v3_pmaps.c   crypto/cms/cms_sd.c             \
	crypto/x509/x509_ext.c     crypto/x509v3/v3_asid.c    crypto/x509v3/v3_prn.c     crypto/cms/cms_smime.c          \
	crypto/x509/x509_lu.c      crypto/x509v3/v3_bcons.c   crypto/x509v3/v3_purp.c    crypto/dsa/dsa_ameth.c          \
	crypto/x509/x509_obj.c     crypto/x509v3/v3_bitst.c   crypto/dsa/dsa_asn1.c      crypto/pkcs12/p12_decr.c        \
	crypto/x509/x509_r2x.c     crypto/x509v3/v3_conf.c    crypto/x509v3/v3_skey.c    crypto/dsa/dsa_depr.c           \
	crypto/x509/x509_req.c     crypto/x509v3/v3_cpols.c   crypto/x509v3/v3_sxnet.c   crypto/dsa/dsa_err.c            \
	crypto/x509/x509_set.c     crypto/x509v3/v3_crld.c    crypto/x509v3/v3_utl.c     crypto/dsa/dsa_gen.c            \
	crypto/x509/x509_trs.c     crypto/x509v3/v3_enum.c    crypto/x509v3/v3err.c      crypto/dsa/dsa_key.c            \
	crypto/x509/x509_txt.c     crypto/x509v3/v3_extku.c   crypto/cms/cms_asn1.c      crypto/dsa/dsa_lib.c            \
	crypto/x509/x509_v3.c      crypto/x509v3/v3_genn.c    crypto/cms/cms_att.c       crypto/dsa/dsa_ossl.c           \
	crypto/x509/x509_vfy.c     crypto/x509v3/v3_ia5.c     crypto/cms/cms_cd.c        crypto/dsa/dsa_pmeth.c          \
	crypto/x509/x509_vpm.c     crypto/x509v3/v3_info.c    crypto/cms/cms_dd.c        crypto/dsa/dsa_prn.c            \
	crypto/x509/x509cset.c     crypto/x509v3/v3_int.c     crypto/cms/cms_enc.c       crypto/dsa/dsa_sign.c           \
	crypto/x509/x509name.c     crypto/x509v3/v3_lib.c     crypto/cms/cms_env.c       crypto/dsa/dsa_vrf.c            \
	crypto/x509/x509rset.c     crypto/x509v3/v3_ncons.c   crypto/cms/cms_err.c       crypto/rsa/rsa_prn.c            \
	crypto/x509/x509spki.c     crypto/ocsp/v3_ocsp.c      crypto/cms/cms_ess.c       crypto/dso/dso_dl.c             \
	crypto/x509/x509type.c     crypto/x509v3/v3_pci.c     crypto/cms/cms_io.c        crypto/dso/dso_dlfcn.c          \
	crypto/x509v3/v3_addr.c    crypto/x509v3/v3_pcia.c    crypto/cms/cms_kari.c      crypto/dso/dso_err.c            \
	crypto/dso/dso_lib.c       crypto/cryptlib.c          crypto/evp/e_seed.c        crypto/ec/ec2_smpl.c            \
	crypto/dso/dso_null.c      crypto/cversion.c          crypto/evp/e_camellia.c    crypto/des/ecb3_enc.c           \
	crypto/dso/dso_openssl.c   crypto/asn1/d2i_pr.c       crypto/ec/ec2_mult.c       crypto/des/ecb_enc.c            \
	crypto/dso/dso_vms.c       crypto/asn1/d2i_pu.c       crypto/evp/e_rc5.c         crypto/rsa/rsa_saos.c           \
	crypto/dso/dso_win32.c     crypto/des/des_enc.c       crypto/evp/e_xcbc_d.c      crypto/rsa/rsa_pk1.c            \
	crypto/modes/cbc128.c      crypto/ec/ec2_oct.c        crypto/pkcs12/p12_utl.c    crypto/sha/sha1_one.c           \
	crypto/modes/ccm128.c      crypto/o_str.c             crypto/pkcs7/pk7_attr.c    crypto/sha/sha512.c             \
	crypto/modes/cfb128.c      crypto/dh/dh_ameth.c       crypto/md4/md4_one.c       crypto/pkcs12/p12_crt.c         \
	crypto/modes/ctr128.c      crypto/dh/dh_asn1.c        crypto/ec/eck_prn.c        crypto/o_time.c                 \
	crypto/modes/gcm128.c      crypto/dh/dh_check.c       engines/e_capi.c           crypto/ec/ecp_mont.c            \
	crypto/modes/ofb128.c      crypto/dh/dh_depr.c        crypto/ec/ecp_nist.c       crypto/rsa/rsa_oaep.c           \
	crypto/modes/xts128.c      crypto/dh/dh_err.c         crypto/ec/ecp_nistp224.c   crypto/pkcs12/p12_crpt.c        \
	crypto/modes/cts128.c      crypto/dh/dh_gen.c         crypto/ec/ecp_nistp256.c   crypto/md4/md4_dgst.c           \
	crypto/modes/wrap128.c     crypto/dh/dh_kdf.c         crypto/ec/ecp_nistp521.c   crypto/rsa/rsa_null.c           \
	crypto/des/cfb64ede.c      crypto/dh/dh_key.c         engines/e_padlock.c        crypto/ec/ecp_nistputil.c       \
	crypto/des/cfb64enc.c      crypto/dh/dh_lib.c         crypto/ec/ecp_oct.c        crypto/pkcs12/p12_attr.c        \
   	crypto/des/cfb_enc.c       crypto/dh/dh_pmeth.c       crypto/ec/ecp_smpl.c       crypto/rand/md_rand.c           \
	crypto/cmac/cm_ameth.c     crypto/dh/dh_prn.c         crypto/ebcdic.c            crypto/pkcs12/p12_asn.c         \
	crypto/cmac/cm_pmeth.c     crypto/dh/dh_rfc5114.c     crypto/ec/ec_ameth.c       crypto/rsa/rsa_none.c           \
	crypto/cmac/cmac.c         crypto/evp/digest.c        crypto/ec/ec_asn1.c        crypto/mdc2/mdc2dgst.c          \
	crypto/comp/comp_err.c     crypto/evp/e_aes.c         crypto/ec/ec_check.c       crypto/rsa/rsa_lib.c            \
	crypto/comp/comp_lib.c     crypto/evp/e_rc2.c         crypto/ec/ec_curve.c       crypto/camellia/cmll_ofb.c      \
	crypto/conf/conf_api.c     crypto/evp/e_rc4.c         crypto/ec/ec_cvt.c         crypto/camellia/cmll_ecb.c      \
	crypto/conf/conf_def.c     crypto/evp/e_bf.c          crypto/ec/ec_err.c         crypto/camellia/cmll_misc.c     \
	crypto/conf/conf_err.c     crypto/evp/e_des.c         crypto/ec/ec_key.c         crypto/des/enc_read.c           \
	crypto/conf/conf_lib.c     crypto/evp/e_des3.c        crypto/ec/ec_lib.c         crypto/des/enc_writ.c           \
	crypto/conf/conf_mall.c    crypto/evp/e_cast.c        crypto/ec/ec_mult.c        crypto/evp/encode.c             \
	crypto/conf/conf_mod.c     crypto/evp/e_idea.c        crypto/ec/ec_oct.c         crypto/engine/eng_all.c         \
	crypto/conf/conf_sap.c     crypto/evp/e_null.c        crypto/ec/ec_pmeth.c       crypto/engine/eng_cnf.c         \
	crypto/cpt_err.c           crypto/evp/e_old.c         crypto/ec/ec_print.c       crypto/engine/eng_cryptodev.c   \
	crypto/engine/eng_ctrl.c   crypto/engine/eng_dyn.c    crypto/engine/eng_err.c    crypto/evp/e_aes_cbc_hmac_sha1.c\
	crypto/engine/eng_fat.c    crypto/engine/eng_init.c   crypto/engine/eng_lib.c    crypto/ts/ts_rsp_verify.c       \
	crypto/engine/eng_list.c   crypto/engine/eng_pkey.c   crypto/engine/eng_rdrand.c crypto/engine/eng_openssl.c     \
	crypto/engine/eng_table.c  crypto/err/err.c           crypto/err/err_all.c       crypto/md5/md5_dgst.c           \
	crypto/err/err_prn.c       crypto/asn1/evp_asn1.c     crypto/pkcs12/p12_add.c    crypto/evp/e_rc4_hmac_md5.c     \
	crypto/evp/evp_cnf.c       crypto/ocsp/ocsp_asn.c     crypto/x509v3/pcy_cache.c  crypto/asn1/t_bitst.c           \
	crypto/evp/evp_enc.c       crypto/ocsp/ocsp_cl.c      crypto/x509v3/pcy_data.c   crypto/x509/t_crl.c             \
	crypto/evp/evp_err.c       crypto/ocsp/ocsp_err.c     crypto/x509v3/pcy_lib.c    crypto/asn1/t_pkey.c            \
	crypto/evp/evp_key.c       crypto/ocsp/ocsp_ext.c     crypto/x509v3/pcy_map.c    crypto/x509/t_req.c             \
	crypto/evp/evp_lib.c       crypto/ocsp/ocsp_ht.c      crypto/x509v3/pcy_node.c   crypto/asn1/t_spki.c            \
	crypto/evp/evp_pbe.c       crypto/ocsp/ocsp_lib.c     crypto/x509v3/pcy_tree.c   crypto/x509/t_x509.c            \
	crypto/evp/evp_pkey.c      crypto/ocsp/ocsp_prn.c     crypto/des/pcbc_enc.c      crypto/md5/md5_one.c            \
	crypto/ex_data.c           crypto/ocsp/ocsp_srv.c     crypto/asn1/p5_pbe.c       crypto/asn1/tasn_dec.c          \
	crypto/ocsp/ocsp_vfy.c     crypto/asn1/p5_pbev2.c     crypto/asn1/tasn_enc.c     crypto/evp/names.c              \
	crypto/asn1/f_int.c        crypto/des/ofb64ede.c      crypto/asn1/p8_pkey.c      crypto/asn1/tasn_fre.c          \
	crypto/asn1/f_string.c     crypto/des/ofb64enc.c      crypto/rand/rand_egd.c     crypto/asn1/tasn_new.c          \
	crypto/des/fcrypt.c        crypto/des/ofb_enc.c       crypto/rand/rand_err.c     crypto/asn1/tasn_prn.c          \
	crypto/des/fcrypt_b.c      crypto/des/qud_cksm.c      crypto/rand/rand_lib.c     crypto/asn1/tasn_typ.c          \
	crypto/fips_ers.c          crypto/evp/p5_crpt.c       crypto/rand/rand_nw.c      crypto/asn1/tasn_utl.c          \
	crypto/hmac/hm_ameth.c     crypto/evp/p5_crpt2.c      crypto/rand/rand_os2.c     crypto/engine/tb_asnmth.c       \
	crypto/hmac/hm_pmeth.c     crypto/evp/p_dec.c         crypto/rand/rand_unix.c    crypto/engine/tb_cipher.c       \
	crypto/hmac/hmac.c         crypto/evp/p_enc.c         crypto/rand/rand_win.c     crypto/engine/tb_dh.c           \
	crypto/asn1/i2d_pr.c       crypto/evp/p_lib.c         crypto/rand/randfile.c     crypto/engine/tb_digest.c       \
	crypto/asn1/i2d_pu.c       crypto/evp/p_open.c        crypto/des/rand_key.c      crypto/engine/tb_dsa.c          \
	crypto/evp/p_seal.c        crypto/rc2/rc2_cbc.c       crypto/pkcs12/p12_mutl.c   crypto/rsa/rsa_sign.c           \
	crypto/lhash/lh_stats.c    crypto/evp/p_sign.c        crypto/rc2/rc2_ecb.c       crypto/mem_dbg.c                \
	crypto/lhash/lhash.c       crypto/evp/p_verify.c      crypto/rc2/rc2_skey.c      crypto/engine/tb_pkmeth.c       \
	crypto/evp/pmeth_fn.c      crypto/rc2/rc2cfb64.c      crypto/engine/tb_rand.c    crypto/rsa/rsa_pss.c            \
	crypto/evp/pmeth_gn.c      crypto/rc2/rc2ofb64.c      crypto/engine/tb_rsa.c     crypto/rsa/rsa_pmeth.c          \
	crypto/evp/pmeth_lib.c     crypto/rc4/rc4_enc.c       crypto/pkcs12/p12_p8e.c    crypto/des/set_key.c            \
	crypto/evp/m_md2.c         crypto/pem/pem_all.c       crypto/rc4/rc4_skey.c      crypto/ts/ts_err.c              \
	crypto/evp/m_md4.c         crypto/pem/pem_err.c       crypto/pkcs12/p12_npas.c   crypto/rsa/rsa_ssl.c            \
	crypto/evp/m_md5.c         crypto/pem/pem_info.c      crypto/des/read2pwd.c      crypto/ui/ui_err.c              \
	crypto/evp/m_mdc2.c        crypto/pem/pem_lib.c       crypto/des/rpc_enc.c       crypto/ui/ui_lib.c              \
	crypto/evp/m_null.c        crypto/pem/pem_oth.c       crypto/rsa/rsa_ameth.c     crypto/ui/ui_openssl.c          \
	crypto/evp/m_ripemd.c      crypto/pem/pem_pk8.c       crypto/rsa/rsa_asn1.c      crypto/ui/ui_util.c             \
	crypto/pem/pem_pkey.c      crypto/rsa/rsa_chk.c       crypto/uid.c               crypto/pkcs12/p12_kiss.c        \
	crypto/evp/m_sha1.c        crypto/rsa/rsa_crpt.c      crypto/des/xcbc_enc.c      crypto/mem.c                    \
	crypto/evp/m_sigver.c      crypto/pem/pem_sign.c      crypto/rsa/rsa_depr.c      crypto/txt_db/txt_db.c          \
	crypto/evp/m_wp.c          crypto/pem/pem_x509.c      crypto/camellia/cmll_cbc.c crypto/pkcs7/pk7_doit.c         \
	crypto/ripemd/rmd_dgst.c   crypto/pem/pem_xaux.c      crypto/rsa/rsa_err.c       crypto/camellia/cmll_cfb.c      \
	crypto/ripemd/rmd_one.c    crypto/pem/pvkfmt.c        crypto/rsa/rsa_gen.c       crypto/camellia/cmll_ctr.c      \
    engines/e_dasync.c         crypto/ct/ct_prn.c         crypto/blake2/blake2b.c    crypto/threads_none.c           \
    crypto/rand/rand_vms.c     crypto/bio/b_addr.c        crypto/blake2/blake2s.c    crypto/threads_pthread.c        \
    crypto/ct/ct_x509v3.c      crypto/bio/b_sock2.c       crypto/ec/ecp_nistz256.c   crypto/threads_win.c            \
    crypto/asn1/asn_mstbl.c    crypto/ec/ec_kmeth.c       crypto/evp/scrypt.c        crypto/kdf/tls1_prf.c           \
    crypto/async/async.c       crypto/ec/ecdh_kdf.c       crypto/bn/bn_dh.c          crypto/kdf/kdf_err.c            \
    crypto/async/async_err.c   crypto/ec/ecdh_ossl.c      crypto/bn/bn_intern.c      crypto/blake2/m_blake2b.c       \
    crypto/ec/ecdsa_ossl.c     crypto/asn1/tasn_scn.c     crypto/blake2/m_blake2s.c  crypto/async/arch/async_null.c  \
    crypto/ec/ec_25519.c       crypto/ec/ecdsa_sign.c     crypto/bn/bn_srp.c         crypto/evp/m_md5_sha1.c         \
    crypto/mdc2/mdc2_one.c     crypto/rsa/rsa_ossl.c      crypto/engine/tb_eckey.c   crypto/evp/cmeth_lib.c          \
    crypto/async/async_wait.c  crypto/ec/ecdsa_vrf.c      crypto/kdf/hkdf.c          crypto/mem_sec.c                \
	crypto/modes/ocb128.c      crypto/ct/ct_log.c         crypto/ct/ct_sct.c         crypto/ec/curve25519.c          \
	crypto/x509v3/v3_tlsf.c    crypto/ct/ct_oct.c         crypto/ct/ct_sct_ctx.c     crypto/pkcs12/p12_sbag.c        \
	crypto/ct/ct_b64.c         crypto/ct/ct_policy.c      crypto/ct/ct_vfy.c         crypto/asn1/p5_scrypt.c         \
	crypto/ct/ct_err.c         crypto/poly1305/poly1305.c crypto/init.c              crypto/async/arch/async_win.c   \
    crypto/evp/e_aes_cbc_hmac_sha256.c                    crypto/evp/e_chacha20_poly1305.c                           \
	$(LOCAL_ASM_FILES)   

LOCAL_LDLIBS := -lz -ldl
include $(BUILD_SHARED_LIBRARY)


####################################################libssl#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE    := libssl
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/ \
	$(LOCAL_PATH)/crypto \
	$(LOCAL_PATH)/ssl \

LOCAL_SRC_FILES := \
	ssl/bio_ssl.c        ssl/ssl_cert.c       ssl/ssl_sess.c       ssl/statem/statem_srvr.c  ssl/record/rec_layer_s3.c \
	ssl/d1_lib.c         ssl/s3_cbc.c         ssl/ssl_ciph.c       ssl/ssl_stat.c            ssl/t1_enc.c              \
	ssl/d1_msg.c         ssl/s3_enc.c         ssl/ssl_conf.c       ssl/ssl_txt.c             ssl/t1_ext.c              \
	ssl/d1_srtp.c        ssl/s3_lib.c         ssl/ssl_err.c        ssl/ssl_utst.c            ssl/t1_lib.c              \
	ssl/s3_msg.c         ssl/ssl_init.c       ssl/t1_reneg.c       ssl/statem/statem_lib.c   ssl/record/dtls1_bitmap.c \
	ssl/methods.c        ssl/t1_trce.c        ssl/ssl_lib.c        ssl/statem/statem_clnt.c  ssl/record/ssl3_buffer.c  \
	ssl/pqueue.c         ssl/ssl_mcnf.c       ssl/tls_srp.c        ssl/statem/statem_dtls.c  ssl/record/ssl3_record.c  \
	ssl/ssl_asn1.c       ssl/ssl_rsa.c        ssl/statem/statem.c  ssl/record/rec_layer_d1.c         

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \

LOCAL_SHARED_LIBRARIES := crypto
include $(BUILD_SHARED_LIBRARY)




####################################################libdasync#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE    := dasync
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/ 

LOCAL_SRC_FILES := \
	engines/e_dasync.c

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \

LOCAL_SHARED_LIBRARIES := crypto
include $(BUILD_SHARED_LIBRARY)




####################################################libpadlock#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE    := padlock
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/ 

LOCAL_SRC_FILES := \
	engines/e_padlock.c

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \

LOCAL_SHARED_LIBRARIES := crypto
include $(BUILD_SHARED_LIBRARY)


####################################################libcapi#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE    := capi
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/ 

LOCAL_SRC_FILES := \
	engines/e_capi.c

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \

LOCAL_SHARED_LIBRARIES := crypto
include $(BUILD_SHARED_LIBRARY)


####################################################openssl#######################################################
include $(CLEAR_VARS)

LOCAL_MODULE    := openssl
LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/include \
	$(LOCAL_PATH)/ 

LOCAL_SRC_FILES := \
	apps/app_rand.c  \
	apps/apps.c  \
	apps/asn1pars.c  \
	apps/ca.c  \
	apps/ciphers.c  \
	apps/cms.c  \
	apps/crl.c  \
	apps/crl2p7.c  \
	apps/dgst.c  \
	apps/dhparam.c  \
	apps/dsa.c  \
	apps/dsaparam.c  \
	apps/ec.c  \
	apps/ecparam.c  \
	apps/enc.c  \
	apps/engine.c  \
	apps/errstr.c  \
	apps/gendsa.c  \
	apps/genpkey.c  \
	apps/genrsa.c  \
	apps/nseq.c  \
	apps/ocsp.c  \
	apps/openssl.c  \
	apps/opt.c \
	apps/passwd.c  \
	apps/pkcs7.c  \
	apps/pkcs8.c  \
	apps/pkcs12.c  \
	apps/pkey.c  \
	apps/pkeyparam.c  \
	apps/pkeyutl.c  \
	apps/prime.c  \
	apps/rand.c  \
	apps/rehash.c \
	apps/req.c  \
	apps/rsa.c  \
	apps/rsautl.c  \
	apps/s_cb.c  \
	apps/s_client.c  \
	apps/s_server.c  \
	apps/s_socket.c  \
	apps/s_time.c  \
	apps/sess_id.c  \
	apps/smime.c  \
	apps/speed.c  \
	apps/spkac.c  \
	apps/srp.c  \
	apps/ts.c  \
	apps/verify.c  \
	apps/version.c  \
	apps/vms_decc_init.c  \
	apps/x509.c  \

LOCAL_CFLAGS += \
	-DOPENSSLDIR="\"/system/lib/ssl\"" \
	-DENGINESDIR="\"/system/lib/ssl/engines\"" \
	-DMONOLITH \
	-DOPENSSL_THREADS  \

LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

LOCAL_MODULE_PATH = $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_SHARED_LIBRARIES += libcrypto libssl
include $(BUILD_EXECUTABLE)
