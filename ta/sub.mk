global-incdirs-y += include
srcs-y += dbstore_ta.c
srcs-y += LittleD/strcat.c
srcs-y += LittleD/atoi.c
srcs-y += LittleD/dbobjects/relation.c
srcs-y += LittleD/dbobjects/tuple.c
srcs-y += LittleD/dbmm/db_query_mm.c
srcs-y += LittleD/dbstorage/dbstorage.c
srcs-y += LittleD/dblogic/compare_tuple.c
srcs-y += LittleD/dblogic/eet.c
srcs-y += LittleD/dbops/scan.c
srcs-y += LittleD/dbops/select.c
srcs-y += LittleD/dbops/project.c
srcs-y += LittleD/dbops/ntjoin.c
srcs-y += LittleD/dbops/osijoin.c
srcs-y += LittleD/dbops/sort.c
srcs-y += LittleD/dbops/aggregate.c
srcs-y += LittleD/dbops/db_ops.c
srcs-y += LittleD/dbindex/dbindex.c
srcs-y += LittleD/dboutput/query_output.c
srcs-y += LittleD/dbparser/dblexer.c
srcs-y += LittleD/dbparser/dbparseexpr.c
srcs-y += LittleD/dbparser/dbcreate.c
srcs-y += LittleD/dbparser/dbinsert.c
srcs-y += LittleD/dbparser/dbparser.c

#libnames += sqlite3
#libdeps += ../libs/libsqlite3.a

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
