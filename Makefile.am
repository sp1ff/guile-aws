GOBJECTS = $(GUILE_SOURCES:%.scm=%.go) $(JSON_SOURCES:.normal.json=.go)

nobase_mod_DATA = $(SOURCES) $(NOCOMP_SOURCES)
nobase_go_DATA = $(GOBJECTS)

# Make sure source files are installed first, so that the mtime of
# installed compiled files is greater than that of installed source
# files.  See
# <http://lists.gnu.org/archive/html/guile-devel/2010-07/msg00125.html>
# for details.
guile_install_go_files = install-nobase_goDATA
$(guile_install_go_files): install-nobase_modDATA

CLEANFILES = $(GOBJECTS)
EXTRA_DIST = $(SOURCES) $(NOCOMP_SOURCES)
GUILE_WARNINGS = -Wunbound-variable -Warity-mismatch -Wformat
SUFFIXES = .scm .go
.scm.go:
	$(AM_V_GEN)$(top_builddir)/pre-inst-env $(GUILE_TOOLS) compile $(GUILE_WARNINGS) -o "$@" "$<"

moddir=$(prefix)/share/guile/site/$(GUILE_EFFECTIVE_VERSION)
godir=$(libdir)/guile/$(GUILE_EFFECTIVE_VERSION)/site-ccache

GUILE_SOURCES =             \
  aws/base.scm              \
  aws/serialize.scm         \
  aws/request.scm           \
  aws/utils/json.scm        \
  language/aws/spec.scm

JSON_SOURCES = \
  aws/api/ce-2017-10-25.normal.json \
  aws/api/cloudfront-2019-03-26.normal.json \
  aws/api/ebs-2019-11-02.normal.json \
  aws/api/elasticfilesystem-2015-02-01.normal.json \
  aws/api/ecr-2015-09-21.normal.json \
  aws/api/ecs-2014-11-13.normal.json \
  aws/api/ec2-2016-11-15.normal.json \
  aws/api/s3-2006-03-01.normal.json \
  aws/api/route53-2013-04-01.normal.json

$(JSON_SOURCES:.normal.json=.go): %.go: %.normal.json aws/base.scm language/aws/spec.scm
	$(AM_V_GEN)$(top_builddir)/pre-inst-env $(GUILE_TOOLS) \
	  compile $(GUILE_WARNINGS) -O1 --from=aws \
	  -o "$@" "$<"


SOURCES = $(GUILE_SOURCES) $(JSON_SOURCES)

TEST_EXTENSIONS = .scm

SCM_TESTS = \
  tests/serialize.scm

TESTS = $(SCM_TESTS)

EXTRA_DIST += $(TESTS)

AM_TESTS_ENVIRONMENT = abs_top_srcdir="$(abs_top_srcdir)" GUILE_AUTO_COMPILE=0

SCM_LOG_DRIVER =                                          \
  $(top_builddir)/pre-inst-env                            \
  $(GUILE) --no-auto-compile -e main                      \
      $(top_srcdir)/build-aux/test-driver.scm

AM_SCM_LOG_DRIVER_FLAGS = --brief=yes

EXTRA_DIST +=					\
  pre-inst-env.in				\
  build-aux/test-driver.scm
