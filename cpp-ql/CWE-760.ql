// Auto-generated; CWE-760; number of APIs 78
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("RAND_bytes%") and qn = "RAND_bytes" or
  target.getQualifiedName().matches("RAND_priv_bytes%") and qn = "RAND_priv_bytes" or
  target.getQualifiedName().matches("RAND_pseudo_bytes%") and qn = "RAND_pseudo_bytes" or
  target.getQualifiedName().matches("RAND_seed%") and qn = "RAND_seed" or
  target.getQualifiedName().matches("RAND_add%") and qn = "RAND_add" or
  target.getQualifiedName().matches("RAND_load_file%") and qn = "RAND_load_file" or
  target.getQualifiedName().matches("RAND_poll%") and qn = "RAND_poll" or
  target.getQualifiedName().matches("RAND_status%") and qn = "RAND_status" or
  target.getQualifiedName().matches("RAND_write_file%") and qn = "RAND_write_file" or
  target.getQualifiedName().matches("RAND_file_name%") and qn = "RAND_file_name" or
  target.getQualifiedName().matches("arc4random%") and qn = "arc4random" or
  target.getQualifiedName().matches("arc4random_buf%") and qn = "arc4random_buf" or
  target.getQualifiedName().matches("arc4random_uniform%") and qn = "arc4random_uniform" or
  target.getQualifiedName().matches("random%") and qn = "random" or
  target.getQualifiedName().matches("srandom%") and qn = "srandom" or
  target.getQualifiedName().matches("rand%") and qn = "rand" or
  target.getQualifiedName().matches("srand%") and qn = "srand" or
  target.getQualifiedName().matches("drand48%") and qn = "drand48" or
  target.getQualifiedName().matches("erand48%") and qn = "erand48" or
  target.getQualifiedName().matches("lrand48%") and qn = "lrand48" or
  target.getQualifiedName().matches("mrand48%") and qn = "mrand48" or
  target.getQualifiedName().matches("seed48%") and qn = "seed48" or
  target.getQualifiedName().matches("initstate%") and qn = "initstate" or
  target.getQualifiedName().matches("setstate%") and qn = "setstate" or
  target.getQualifiedName().matches("getrandom%") and qn = "getrandom" or
  target.getQualifiedName().matches("getentropy%") and qn = "getentropy" or
  target.getQualifiedName().matches("std%::rand%") and qn = "std::rand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "rand" and
    qn = "std::rand"
  ) or
  target.getQualifiedName().matches("std%::srand%") and qn = "std::srand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "srand" and
    qn = "std::srand"
  ) or
  target.getQualifiedName().matches("std%::random_device%") and qn = "std::random_device" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "random_device" and
    qn = "std::random_device"
  ) or
  target.getQualifiedName().matches("std%::mt19937%") and qn = "std::mt19937" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "mt19937" and
    qn = "std::mt19937"
  ) or
  target.getQualifiedName().matches("std%::mt19937_64%") and qn = "std::mt19937_64" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "mt19937_64" and
    qn = "std::mt19937_64"
  ) or
  target.getQualifiedName().matches("std%::default_random_engine%") and qn = "std::default_random_engine" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "default_random_engine" and
    qn = "std::default_random_engine"
  ) or
  target.getQualifiedName().matches("std%::minstd_rand%") and qn = "std::minstd_rand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "minstd_rand" and
    qn = "std::minstd_rand"
  ) or
  target.getQualifiedName().matches("std%::minstd_rand0%") and qn = "std::minstd_rand0" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "minstd_rand0" and
    qn = "std::minstd_rand0"
  ) or
  target.getQualifiedName().matches("std%::linear_congruential_engine%") and qn = "std::linear_congruential_engine" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "linear_congruential_engine" and
    qn = "std::linear_congruential_engine"
  ) or
  target.getQualifiedName().matches("boost%::random%::mt19937%") and qn = "boost::random::mt19937" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "random") and
    memberFunc.getName() = "mt19937" and
    qn = "boost::random::mt19937"
  ) or
  target.getQualifiedName().matches("boost%::random%::minstd_rand%") and qn = "boost::random::minstd_rand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "random") and
    memberFunc.getName() = "minstd_rand" and
    qn = "boost::random::minstd_rand"
  ) or
  target.getQualifiedName().matches("boost%::random%::rand48%") and qn = "boost::random::rand48" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "random") and
    memberFunc.getName() = "rand48" and
    qn = "boost::random::rand48"
  ) or
  target.getQualifiedName().matches("boost%::random%::linear_congruential_engine%") and qn = "boost::random::linear_congruential_engine" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "random") and
    memberFunc.getName() = "linear_congruential_engine" and
    qn = "boost::random::linear_congruential_engine"
  ) or
  target.getQualifiedName().matches("CryptGenRandom%") and qn = "CryptGenRandom" or
  target.getQualifiedName().matches("BCryptGenRandom%") and qn = "BCryptGenRandom" or
  target.getQualifiedName().matches("RtlGenRandom%") and qn = "RtlGenRandom" or
  target.getQualifiedName().matches("gcry_randomize%") and qn = "gcry_randomize" or
  target.getQualifiedName().matches("gcry_create_nonce%") and qn = "gcry_create_nonce" or
  target.getQualifiedName().matches("gcry_mpi_randomize%") and qn = "gcry_mpi_randomize" or
  target.getQualifiedName().matches("mbedtls_ctr_drbg_seed%") and qn = "mbedtls_ctr_drbg_seed" or
  target.getQualifiedName().matches("mbedtls_ctr_drbg_random%") and qn = "mbedtls_ctr_drbg_random" or
  target.getQualifiedName().matches("mbedtls_hmac_drbg_seed%") and qn = "mbedtls_hmac_drbg_seed" or
  target.getQualifiedName().matches("mbedtls_hmac_drbg_random%") and qn = "mbedtls_hmac_drbg_random" or
  target.getQualifiedName().matches("mbedtls_entropy_func%") and qn = "mbedtls_entropy_func" or
  target.getQualifiedName().matches("mbedtls_entropy_gather%") and qn = "mbedtls_entropy_gather" or
  target.getQualifiedName().matches("mbedtls_entropy_add_source%") and qn = "mbedtls_entropy_add_source" or
  target.getQualifiedName().matches("gnutls_rnd%") and qn = "gnutls_rnd" or
  target.getQualifiedName().matches("gnutls_rnd_refresh%") and qn = "gnutls_rnd_refresh" or
  target.getQualifiedName().matches("PK11_GenerateRandom%") and qn = "PK11_GenerateRandom" or
  target.getQualifiedName().matches("PK11_GenerateRandomData%") and qn = "PK11_GenerateRandomData" or
  target.getQualifiedName().matches("Botan%::AutoSeeded_RNG%") and qn = "Botan::AutoSeeded_RNG" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "AutoSeeded_RNG" and
    qn = "Botan::AutoSeeded_RNG"
  ) or
  target.getQualifiedName().matches("Botan%::System_RNG%") and qn = "Botan::System_RNG" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "System_RNG" and
    qn = "Botan::System_RNG"
  ) or
  target.getQualifiedName().matches("Botan%::HMAC_DRBG%") and qn = "Botan::HMAC_DRBG" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "HMAC_DRBG" and
    qn = "Botan::HMAC_DRBG"
  ) or
  target.getQualifiedName().matches("Botan%::RandomNumberGenerator%::randomize%") and qn = "Botan::RandomNumberGenerator::randomize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "RandomNumberGenerator") and
    memberFunc.getName() = "randomize" and
    qn = "Botan::RandomNumberGenerator::randomize"
  ) or
  target.getQualifiedName().matches("Botan%::RandomNumberGenerator%::random_vec%") and qn = "Botan::RandomNumberGenerator::random_vec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "RandomNumberGenerator") and
    memberFunc.getName() = "random_vec" and
    qn = "Botan::RandomNumberGenerator::random_vec"
  ) or
  target.getQualifiedName().matches("CryptoPP%::AutoSeededRandomPool%") and qn = "CryptoPP::AutoSeededRandomPool" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "AutoSeededRandomPool" and
    qn = "CryptoPP::AutoSeededRandomPool"
  ) or
  target.getQualifiedName().matches("CryptoPP%::OS_GenerateRandomBlock%") and qn = "CryptoPP::OS_GenerateRandomBlock" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "OS_GenerateRandomBlock" and
    qn = "CryptoPP::OS_GenerateRandomBlock"
  ) or
  target.getQualifiedName().matches("CryptoPP%::NonblockingRng%") and qn = "CryptoPP::NonblockingRng" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "NonblockingRng" and
    qn = "CryptoPP::NonblockingRng"
  ) or
  target.getQualifiedName().matches("CryptoPP%::RandomPool%") and qn = "CryptoPP::RandomPool" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "RandomPool" and
    qn = "CryptoPP::RandomPool"
  ) or
  target.getQualifiedName().matches("CryptoPP%::RDRAND%") and qn = "CryptoPP::RDRAND" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "RDRAND" and
    qn = "CryptoPP::RDRAND"
  ) or
  target.getQualifiedName().matches("OpenSSL%::RAND_bytes%") and qn = "OpenSSL::RAND_bytes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "RAND_bytes" and
    qn = "OpenSSL::RAND_bytes"
  ) or
  target.getQualifiedName().matches("OpenSSL%::RAND_priv_bytes%") and qn = "OpenSSL::RAND_priv_bytes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "RAND_priv_bytes" and
    qn = "OpenSSL::RAND_priv_bytes"
  ) or
  target.getQualifiedName().matches("OpenSSL%::RAND_pseudo_bytes%") and qn = "OpenSSL::RAND_pseudo_bytes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "RAND_pseudo_bytes" and
    qn = "OpenSSL::RAND_pseudo_bytes"
  ) or
  target.getQualifiedName().matches("OpenSSL%::RAND_poll%") and qn = "OpenSSL::RAND_poll" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "RAND_poll" and
    qn = "OpenSSL::RAND_poll"
  ) or
  target.getQualifiedName().matches("NSS%::PK11_GenerateRandom%") and qn = "NSS::PK11_GenerateRandom" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "PK11_GenerateRandom" and
    qn = "NSS::PK11_GenerateRandom"
  ) or
  target.getQualifiedName().matches("NSS%::PK11_GenerateRandomData%") and qn = "NSS::PK11_GenerateRandomData" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "PK11_GenerateRandomData" and
    qn = "NSS::PK11_GenerateRandomData"
  ) or
  target.getQualifiedName().matches("gettimeofday%") and qn = "gettimeofday" or
  target.getQualifiedName().matches("time%") and qn = "time" or
  target.getQualifiedName().matches("std%::time%") and qn = "std::time" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "time" and
    qn = "std::time"
  ) or
  target.getQualifiedName().matches("clock%") and qn = "clock" or
  target.getQualifiedName().matches("clock_gettime%") and qn = "clock_gettime" or
  target.getQualifiedName().matches("QueryPerformanceCounter%") and qn = "QueryPerformanceCounter"
}

predicate isInSourceCode(FunctionCall call) {
  call.getLocation().getFile().getRelativePath() != ""
}

from FunctionCall call, Function targetFunc, Function enclosingFunc, string qn
where
  targetFunc = call.getTarget() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingFunction() and
  isInSourceCode(call)
select 
"Path: " + call.getLocation().getFile(),
"call function: " + call.getLocation().getStartLine()+":"+call.getLocation().getStartColumn()+
"-"+call.getLocation().getEndLine()+":"+call.getLocation().getEndColumn(),
"call in function: " + enclosingFunc.getName() + "@" +
enclosingFunc.getLocation().getStartLine() + "-" +
enclosingFunc.getBlock().getLocation().getEndLine(),
"callee=" + qn,
"basic block: " + call.getBasicBlock().getStart().getLocation().getStartLine() + ":" +call.getBasicBlock().getStart().getLocation().getStartColumn()+
"-"+ call.getBasicBlock().getEnd().getLocation().getEndLine() + ":" + call.getBasicBlock().getEnd().getLocation().getEndColumn()
