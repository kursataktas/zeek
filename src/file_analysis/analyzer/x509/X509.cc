// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "X509.h"
#include "Event.h"
#include "x509-extension_pac.h"

#include "events.bif.h"
#include "types.bif.h"

#include "file_analysis/Manager.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/opensslconf.h>
#include <openssl/err.h>

#include "Asn1Time.h"

using namespace file_analysis;

IMPLEMENT_SERIAL(X509Val, SER_X509_VAL);

file_analysis::X509::X509(RecordVal* args, file_analysis::File* file)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("X509"), args, file)
	{
	cert_data.clear();
	}

bool file_analysis::X509::DeliverStream(const u_char* data, uint64 len)
	{
	// just add it to the data we have so far, since we cannot do anything else anyways...
	cert_data.append(reinterpret_cast<const char*>(data), len);
	return true;
	}

bool file_analysis::X509::Undelivered(uint64 offset, uint64 len)
	{
	return false;
	}

bool file_analysis::X509::EndOfFile()
	{
	// ok, now we can try to parse the certificate with openssl. Should
	// be rather straightforward...
	const unsigned char* cert_char = reinterpret_cast<const unsigned char*>(cert_data.data());

	::X509* ssl_cert = d2i_X509(NULL, &cert_char, cert_data.size());
	if ( ! ssl_cert )
		{
		reporter->Weird(fmt("Could not parse X509 certificate (fuid %s)", GetFile()->GetID().c_str()));
		return false;
		}

	X509Val* cert_val = new X509Val(ssl_cert); // cert_val takes ownership of ssl_cert

	// parse basic information into record.
	RecordVal* cert_record = ParseCertificate(cert_val, GetFile()->GetID().c_str());

	// and send the record on to scriptland
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(cert_val->Ref());
	vl->append(cert_record->Ref()); // we Ref it here, because we want to keep a copy around for now...
	mgr.QueueEvent(x509_certificate, vl);

	// after parsing the certificate - parse the extensions...

	int num_ext = X509_get_ext_count(ssl_cert);
	for ( int k = 0; k < num_ext; ++k )
		{
		X509_EXTENSION* ex = X509_get_ext(ssl_cert, k);
		if ( ! ex )
			continue;

		ParseExtension(ex);
		}

	// X509_free(ssl_cert); We do _not_ free the certificate here. It is refcounted
	// inside the X509Val that is sent on in the cert record to scriptland.
	//
	// The certificate will be freed when the last X509Val is Unref'd.

	Unref(cert_record); // Unref the RecordVal that we kept around from ParseCertificate
	Unref(cert_val); // Same for cert_val

	return false;
	}

RecordVal* file_analysis::X509::ParseCertificate(X509Val* cert_val, const char* fid)
	{
	::X509* ssl_cert = cert_val->GetCertificate();

	char buf[2048]; // we need a buffer for some of the openssl functions
	memset(buf, 0, sizeof(buf));

	RecordVal* pX509Cert = new RecordVal(BifType::Record::X509::Certificate);
	BIO *bio = BIO_new(BIO_s_mem());

	pX509Cert->Assign(0, new Val((uint64) X509_get_version(ssl_cert) + 1, TYPE_COUNT));
	i2a_ASN1_INTEGER(bio, X509_get_serialNumber(ssl_cert));
	int len = BIO_read(bio, buf, sizeof(buf));
	pX509Cert->Assign(1, new StringVal(len, buf));
	BIO_reset(bio);

	X509_NAME_print_ex(bio, X509_get_subject_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, buf, sizeof(buf));
	pX509Cert->Assign(2, new StringVal(len, buf));
	BIO_reset(bio);

	X509_NAME *subject_name = X509_get_subject_name(ssl_cert);
	// extract the most specific (last) common name from the subject
	int namepos = -1;
	for ( ;; )
		{
		int j = X509_NAME_get_index_by_NID(subject_name, NID_commonName, namepos);
		if ( j == -1 )
			break;

		namepos = j;
		}

	if ( namepos != -1 )
		{
		// we found a common name
		ASN1_STRING_print(bio, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, namepos)));
		len = BIO_gets(bio, buf, sizeof(buf));
		pX509Cert->Assign(4, new StringVal(len, buf));
		BIO_reset(bio);
		}

	X509_NAME_print_ex(bio, X509_get_issuer_name(ssl_cert), 0, XN_FLAG_RFC2253);
	len = BIO_gets(bio, buf, sizeof(buf));
	pX509Cert->Assign(3, new StringVal(len, buf));
	BIO_free(bio);

	pX509Cert->Assign(5, new Val(GetTimeFromAsn1(X509_get_notBefore(ssl_cert), fid, reporter), TYPE_TIME));
	pX509Cert->Assign(6, new Val(GetTimeFromAsn1(X509_get_notAfter(ssl_cert), fid, reporter), TYPE_TIME));

	// we only read 255 bytes because byte 256 is always 0.
	// if the string is longer than 255, that will be our null-termination,
	// otherwhise i2t does null-terminate.
	if ( ! i2t_ASN1_OBJECT(buf, 255, ssl_cert->cert_info->key->algor->algorithm) )
		buf[0] = 0;

	pX509Cert->Assign(7, new StringVal(buf));

	// Special case for RDP server certificates. For some reason some (all?) RDP server
	// certificates like to specify their key algorithm as md5WithRSAEncryption, which
	// is wrong on so many levels. We catch this special case here and set it to what is
	// actually should be (namely - rsaEncryption), so that OpenSSL will parse out the
	// key later. Otherwise it will just fail to parse the certificate key.

	ASN1_OBJECT* old_algorithm = 0;
	if ( OBJ_obj2nid(ssl_cert->cert_info->key->algor->algorithm) == NID_md5WithRSAEncryption )
		{
		old_algorithm = ssl_cert->cert_info->key->algor->algorithm;
		ssl_cert->cert_info->key->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
		}

	if ( ! i2t_ASN1_OBJECT(buf, 255, ssl_cert->sig_alg->algorithm) )
		buf[0] = 0;

	pX509Cert->Assign(8, new StringVal(buf));

	// Things we can do when we have the key...
	EVP_PKEY *pkey = X509_extract_key(ssl_cert);
	if ( pkey != NULL )
		{
		if ( pkey->type == EVP_PKEY_DSA )
			pX509Cert->Assign(9, new StringVal("dsa"));

		else if ( pkey->type == EVP_PKEY_RSA )
			{
			pX509Cert->Assign(9, new StringVal("rsa"));

			char *exponent = BN_bn2dec(pkey->pkey.rsa->e);
			if ( exponent != NULL )
				{
				pX509Cert->Assign(11, new StringVal(exponent));
				OPENSSL_free(exponent);
				exponent = NULL;
				}
			}
#ifndef OPENSSL_NO_EC
		else if ( pkey->type == EVP_PKEY_EC )
			{
			pX509Cert->Assign(9, new StringVal("ecdsa"));
			pX509Cert->Assign(12, KeyCurve(pkey));
			}
#endif

		// set key algorithm back. We do not have to free the value that we created because (I think) it
		// comes out of a static array from OpenSSL memory.
		if ( old_algorithm )
			ssl_cert->cert_info->key->algor->algorithm = old_algorithm;

		unsigned int length = KeyLength(pkey);
		if ( length > 0 )
			pX509Cert->Assign(10, new Val(length, TYPE_COUNT));

		EVP_PKEY_free(pkey);
		}


	return pX509Cert;
	}

StringVal* file_analysis::X509::GetExtensionFromBIO(BIO* bio)
	{
	BIO_flush(bio);
	ERR_clear_error();
	int length = BIO_pending(bio);

	if ( ERR_peek_error() != 0 )
		{
		char tmp[120];
		ERR_error_string_n(ERR_get_error(), tmp, sizeof(tmp));
		reporter->Weird(fmt("X509::GetExtensionFromBIO: %s", tmp));
		BIO_free_all(bio);
		return 0;
		}

	if ( length == 0 )
		{
		BIO_free_all(bio);
		return new StringVal("");
		}

	char* buffer = (char*) malloc(length);

	if ( ! buffer )
		{
		// Just emit an error here and try to continue instead of aborting
		// because it's unclear the length value is very reliable.
		reporter->Error("X509::GetExtensionFromBIO malloc(%d) failed", length);
		BIO_free_all(bio);
		return 0;
		}

	BIO_read(bio, (void*) buffer, length);
	StringVal* ext_val = new StringVal(length, buffer);

	free(buffer);
	BIO_free_all(bio);

	return ext_val;
	}

// this is nearly replicated in the OCSP analyzer
void file_analysis::X509::ParseExtension(X509_EXTENSION* ex)
	{
	char name[256];
	char oid[256];

	ASN1_OBJECT* ext_asn = X509_EXTENSION_get_object(ex);
	const char* short_name = OBJ_nid2sn(OBJ_obj2nid(ext_asn));

	OBJ_obj2txt(name, 255, ext_asn, 0);
	OBJ_obj2txt(oid, 255, ext_asn, 1);

	int critical = 0;
	if ( X509_EXTENSION_get_critical(ex) != 0 )
		critical = 1;

	BIO *bio = BIO_new(BIO_s_mem());
	if( ! X509V3_EXT_print(bio, ex, 0, 0))
		M_ASN1_OCTET_STRING_print(bio,ex->value);

	StringVal* ext_val = GetExtensionFromBIO(bio);

	if ( ! ext_val )
		ext_val = new StringVal(0, "");

	RecordVal* pX509Ext = new RecordVal(BifType::Record::X509::Extension);
	pX509Ext->Assign(0, new StringVal(name));

	if ( short_name and strlen(short_name) > 0 )
		pX509Ext->Assign(1, new StringVal(short_name));

	pX509Ext->Assign(2, new StringVal(oid));
	pX509Ext->Assign(3, new Val(critical, TYPE_BOOL));
	pX509Ext->Assign(4, ext_val);

	// send off generic extension event
	//
	// and then look if we have a specialized event for the extension we just
	// parsed. And if we have it, we send the specialized event on top of the
	// generic event that we just had. I know, that is... kind of not nice,
	// but I am not sure if there is a better way to do it...
	val_list* vl = new val_list();
	vl->append(GetFile()->GetVal()->Ref());
	vl->append(pX509Ext);

	mgr.QueueEvent(x509_extension, vl);

	// look if we have a specialized handler for this event...
	if ( OBJ_obj2nid(ext_asn) == NID_basic_constraints )
		ParseBasicConstraints(ex);

	else if ( OBJ_obj2nid(ext_asn) == NID_subject_alt_name )
		ParseSAN(ex);

#ifdef NID_ct_cert_scts
	else if ( OBJ_obj2nid(ext_asn) == NID_ct_cert_scts || OBJ_obj2nid(ext_asn) == NID_ct_precert_scts )
#else
	else if ( strcmp(oid, "1.3.6.1.4.1.11129.2.4.2") == 0 || strcmp(oid, "1.3.6.1.4.1.11129.2.4.4") == 0 )
#endif
		ParseSignedCertificateTimestamps(ex);
	}

void file_analysis::X509::ParseSignedCertificateTimestamps(X509_EXTENSION* ext)
	{
	// Ok, signed certificate timestamps are a bit of an odd case out; we don't
	// want to use the (basically nonexistant) OpenSSL functionality to parse them.
	// Instead we have our own, self-written binpac parser to parse just them,
	// which we will initialize here and tear down immediately again.

	ASN1_OCTET_STRING* ext_val = X509_EXTENSION_get_data(ext);
	// the octet string of the extension contains the octet string which in turn
	// contains the SCT. Obviously.

	unsigned char* ext_val_copy = (unsigned char*) OPENSSL_malloc(ext_val->length);
	unsigned char* ext_val_second_pointer = ext_val_copy;
	memcpy(ext_val_copy, ext_val->data, ext_val->length);

	ASN1_OCTET_STRING* inner = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char**) &ext_val_copy, ext_val->length);
	if ( !inner )
		{
		reporter->Error("X509::ParseSignedCertificateTimestamps could not parse inner octet string");
		return;
		}

	binpac::X509Extension::MockConnection* conn = new binpac::X509Extension::MockConnection(this);
	binpac::X509Extension::SignedCertTimestampExt* interp = new binpac::X509Extension::SignedCertTimestampExt(conn);

	try
		{
		interp->NewData(inner->data, inner->data + inner->length);
		}
	catch( const binpac::Exception& e )
		{
		// throw a warning or sth
		reporter->Error("X509::ParseSignedCertificateTimestamps could not parse SCT");
		}

	OPENSSL_free(ext_val_second_pointer);

	interp->FlowEOF();

	delete interp;
	delete conn;
	}

void file_analysis::X509::ParseBasicConstraints(X509_EXTENSION* ex)
	{
	assert(OBJ_obj2nid(X509_EXTENSION_get_object(ex)) == NID_basic_constraints);

	BASIC_CONSTRAINTS *constr = (BASIC_CONSTRAINTS *) X509V3_EXT_d2i(ex);

	if ( constr )
		{
		RecordVal* pBasicConstraint = new RecordVal(BifType::Record::X509::BasicConstraints);
		pBasicConstraint->Assign(0, new Val(constr->ca ? 1 : 0, TYPE_BOOL));

		if ( constr->pathlen )
			pBasicConstraint->Assign(1, new Val((int32_t) ASN1_INTEGER_get(constr->pathlen), TYPE_COUNT));

		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(pBasicConstraint);

		mgr.QueueEvent(x509_ext_basic_constraints, vl);
		BASIC_CONSTRAINTS_free(constr);
		}

	else
		reporter->Weird(fmt("Certificate with invalid BasicConstraint. fuid %s", GetFile()->GetID().c_str()));
	}

void file_analysis::X509::ParseSAN(X509_EXTENSION* ext)
	{
	assert(OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == NID_subject_alt_name);

	GENERAL_NAMES *altname = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
	if ( ! altname )
		{
		reporter->Weird(fmt("Could not parse subject alternative names. fuid %s", GetFile()->GetID().c_str()));
		return;
		}

	VectorVal* names = 0;
	VectorVal* emails = 0;
	VectorVal* uris = 0;
	VectorVal* ips = 0;

	unsigned int otherfields = 0;

	for ( int i = 0; i < sk_GENERAL_NAME_num(altname); i++ )
		{
		GENERAL_NAME *gen = sk_GENERAL_NAME_value(altname, i);
		assert(gen);

		if ( gen->type == GEN_DNS || gen->type == GEN_URI || gen->type == GEN_EMAIL )
			{
			if ( ASN1_STRING_type(gen->d.ia5) != V_ASN1_IA5STRING )
				{
				reporter->Weird(fmt("DNS-field does not contain an IA5String. fuid %s", GetFile()->GetID().c_str()));
				continue;
				}

			const char* name = (const char*) ASN1_STRING_data(gen->d.ia5);
			StringVal* bs = new StringVal(name);

			switch ( gen->type )
				{
				case GEN_DNS:
					if ( names == 0 )
						names = new VectorVal(internal_type("string_vec")->AsVectorType());

					names->Assign(names->Size(), bs);
					break;

				case GEN_URI:
					if ( uris == 0 )
						uris = new VectorVal(internal_type("string_vec")->AsVectorType());

					uris->Assign(uris->Size(), bs);
					break;

				case GEN_EMAIL:
					if ( emails == 0 )
						emails = new VectorVal(internal_type("string_vec")->AsVectorType());

					emails->Assign(emails->Size(), bs);
					break;
				}
			}

		else if ( gen->type == GEN_IPADD )
			{
				if ( ips == 0 )
					ips = new VectorVal(internal_type("addr_vec")->AsVectorType());

				uint32* addr = (uint32*) gen->d.ip->data;

				if( gen->d.ip->length == 4 )
					ips->Assign(ips->Size(), new AddrVal(*addr));

				else if ( gen->d.ip->length == 16 )
					ips->Assign(ips->Size(), new AddrVal(addr));

				else
					{
					reporter->Weird(fmt("Weird IP address length %d in subject alternative name. fuid %s", gen->d.ip->length, GetFile()->GetID().c_str()));
					continue;
					}
			}

		else
			{
			// reporter->Error("Subject alternative name contained unsupported fields. fuid %s", GetFile()->GetID().c_str());
			// This happens quite often - just mark it
			otherfields = 1;
			continue;
			}
		}

		RecordVal* sanExt = new RecordVal(BifType::Record::X509::SubjectAlternativeName);

		if ( names != 0 )
			sanExt->Assign(0, names);

		if ( uris != 0 )
			sanExt->Assign(1, uris);

		if ( emails != 0 )
			sanExt->Assign(2, emails);

		if ( ips != 0 )
			sanExt->Assign(3, ips);

		sanExt->Assign(4, new Val(otherfields, TYPE_BOOL));

		val_list* vl = new val_list();
		vl->append(GetFile()->GetVal()->Ref());
		vl->append(sanExt);
		mgr.QueueEvent(x509_ext_subject_alternative_name, vl);
	GENERAL_NAMES_free(altname);
	}

StringVal* file_analysis::X509::KeyCurve(EVP_PKEY *key)
	{
	assert(key != NULL);

#ifdef OPENSSL_NO_EC
	// well, we do not have EC-Support...
	return NULL;
#else
	if ( key->type != EVP_PKEY_EC )
		{
		// no EC-key - no curve name
		return NULL;
		}

	const EC_GROUP *group;
	int nid;
	if ( (group = EC_KEY_get0_group(key->pkey.ec)) == NULL)
		// I guess we could not parse this
		return NULL;

	nid = EC_GROUP_get_curve_name(group);
	if ( nid == 0 )
		// and an invalid nid...
		return NULL;

	const char * curve_name = OBJ_nid2sn(nid);
	if ( curve_name == NULL )
		return NULL;

	return new StringVal(curve_name);
#endif
	}

unsigned int file_analysis::X509::KeyLength(EVP_PKEY *key)
	{
	assert(key != NULL);

	switch(key->type) {
	case EVP_PKEY_RSA:
		return BN_num_bits(key->pkey.rsa->n);

	case EVP_PKEY_DSA:
		return BN_num_bits(key->pkey.dsa->p);

#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		{
		BIGNUM* ec_order = BN_new();
		if ( ! ec_order )
			// could not malloc bignum?
			return 0;

		const EC_GROUP *group = EC_KEY_get0_group(key->pkey.ec);

		if ( ! group )
			{
			// unknown ex-group
			BN_free(ec_order);
			return 0;
			}

		if ( ! EC_GROUP_get_order(group, ec_order, NULL) )
			{
			// could not get ec-group-order
			BN_free(ec_order);
			return 0;
			}

		unsigned int length = BN_num_bits(ec_order);
		BN_free(ec_order);
		return length;
		}
#endif
	default:
		return 0; // unknown public key type
	}

	reporter->InternalError("cannot be reached");
	}

X509Val::X509Val(::X509* arg_certificate) : OpaqueVal(x509_opaque_type)
	{
	certificate = arg_certificate;
	}

X509Val::X509Val() : OpaqueVal(x509_opaque_type)
	{
	certificate = 0;
	}

X509Val::~X509Val()
	{
	if ( certificate )
		X509_free(certificate);
	}

::X509* X509Val::GetCertificate() const
	{
	return certificate;
	}

bool X509Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_X509_VAL, OpaqueVal);

	unsigned char *buf = NULL;

	int length = i2d_X509(certificate, &buf);

	if ( length < 0 )
		return false;

	bool res = SERIALIZE_STR(reinterpret_cast<const char*>(buf), length);

	OPENSSL_free(buf);
	return res;
	}

bool X509Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal)

	int length;
	unsigned char *certbuf, *opensslbuf;

	if ( ! UNSERIALIZE_STR(reinterpret_cast<char **>(&certbuf), &length) )
		return false;

	opensslbuf = certbuf; // OpenSSL likes to shift pointers around. really.
	certificate = d2i_X509(NULL, const_cast<const unsigned char**>(&opensslbuf), length);
	delete[] certbuf;

	if ( !certificate )
		return false;

	return true;
	}
