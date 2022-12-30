/* Copyright (c) 2004, 2021, Oracle and/or its affiliates.
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2.0,
  as published by the Free Software Foundation.
  This program is also distributed with certain software (including
  but not limited to OpenSSL) that is licensed under separate terms,
  as designated in a particular file or component or in included license
  documentation.  The authors of MySQL hereby grant you an additional
  permission to link the program and your derivative works with the
  separately licensed software that they have included with MySQL.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License, version 2.0, for more details.
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file ha_dbf.cc
  @brief
  The ha_dbf engine is a stubbed storage engine for dbf purposes only;
  it does nothing at this point. Its purpose is to provide a source
  code illustration of how to begin writing new storage engines; see also
  /storage/dbf/ha_dbf.h.
  @details
  ha_dbf will let you create/open/delete tables, but
  nothing further (for dbf, indexes are not supported nor can data
  be stored in the table). Use this dbf as a template for
  implementing the same functionality in your own storage engine. You
  can enable the dbf storage engine in your build by doing the
  following during your build process:<br> ./configure
  --with-dbf-storage-engine
  Once this is done, MySQL will let you create tables with:<br>
  CREATE TABLE <table name> (...) ENGINE=DBF;
  The dbf storage engine is set up to use table locks. It
  implements an dbf "SHARE" that is inserted into a hash by table
  name. You can use this to store information of state that any
  dbf handler object will be able to see when it is using that
  table.
  Please read the object definition in ha_dbf.h before reading the rest
  of this file.
  @note
  When you create an DBF table, the MySQL Server creates a table .frm
  (format) file in the database directory, using the table name as the file
  name as is customary with MySQL. No other files are created. To get an idea
  of what occurs, here is an dbf select that would do a scan of an entire
  table:
  @code
  ha_dbf::store_lock
  ha_dbf::external_lock
  ha_dbf::info
  ha_dbf::rnd_init
  ha_dbf::extra
  ENUM HA_EXTRA_CACHE        Cache record in HA_rrnd()
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::rnd_next
  ha_dbf::extra
  ENUM HA_EXTRA_NO_CACHE     End caching of records (def)
  ha_dbf::external_lock
  ha_dbf::extra
  ENUM HA_EXTRA_RESET        Reset database to after open
  @endcode
  Here you see that the dbf storage engine has 9 rows called before
  rnd_next signals that it has reached the end of its data. Also note that
  the table in question was already opened; had it not been open, a call to
  ha_dbf::open() would also have been necessary. Calls to
  ha_dbf::extra() are hints as to what will be occuring to the request.
  A Longer Dbf can be found called the "Skeleton Engine" which can be
  found on TangentOrg. It has both an engine and a full build environment
  for building a pluggable storage engine.
  Happy coding!<br>
    -Brian
*/

#include "sql_class.h" // MYSQL_HANDLERTON_INTERFACE_VERSION
#include "ha_dbf.h"
#include "probes_mysql.h"
#include "sql_plugin.h"
#include <mysql/psi/mysql_file.h>

#define DBE_EXT ".dbe" // data file extension
#define DBI_EXT ".dbi" // index file extension

mysql_mutex_t dbf_mutex;

static PSI_memory_key key_memory_dbf_share;//内存检测

static PSI_mutex_key key_mutex_dbf, key_mutex_Dbf_share_mutex;//两个锁，一个分配给dbf_mutex，一个分配给share->mutex

static PSI_mutex_info all_dbf_mutexes[]=//官方要求，要有info来注册
        {
                { &key_mutex_dbf, "dbf", PSI_FLAG_GLOBAL},
                { &key_mutex_Dbf_share_mutex, "Dbf_share::mutex", 0}
        };

static PSI_memory_info all_dbf_memory[]=//官方要求，要有info来注册
        {
                { &key_memory_dbf_share, "dbf_share", PSI_FLAG_GLOBAL}
        };

static void init_dbf_psi_keys(void)
{
    const char* category= "dbf";
    int count;
    count= array_elements(all_dbf_mutexes); //用array_elements 函数来数有多少条信息
    mysql_mutex_register(category, all_dbf_mutexes, count); //注册锁
    count= array_elements(all_dbf_memory); 
    mysql_memory_register(category, all_dbf_memory, count); //注册内存
}

static HASH dbf_open_tables;
static handler *dbf_create_handler(handlerton *hton,
                                   TABLE_SHARE *table,
                                   MEM_ROOT *mem_root);

handlerton *dbf_hton; //handerton类型的指针

/* Interface to mysqld, to check system tables supported by SE */
static const char *dbf_system_database();
static bool dbf_is_supported_system_table(const char *db,
                                          const char *table_name,
                                          bool is_sql_layer_system_table);


//dbf_get_key也是由example模块给出。在my_mutex_init中使用
static uchar* dbf_get_key(Dbf_share *share, size_t *length,
                          my_bool not_used MY_ATTRIBUTE((unused)))
{
    *length=share->table_name_length;
    return (uchar*) share->table_name;
}

Dbf_share::Dbf_share()
{
    thr_lock_init(&lock);//初始化锁
}

static int dbf_init_func(void *p)
{
    DBUG_ENTER("dbf_init_func");
    //初始化PSI类型
    init_dbf_psi_keys();
    //初始化锁，将key_mutex_dbf赋给dbf_mutex
    mysql_mutex_init(key_mutex_dbf, &dbf_mutex, MY_MUTEX_INIT_FAST);
    //初始化哈希表
    (void) my_hash_init(&dbf_open_tables,system_charset_info,32,0,0,
                        (my_hash_get_key) dbf_get_key,0,0,
                        key_memory_dbf_share);

    dbf_hton = (handlerton *)p; //分配内存
    dbf_hton->state = SHOW_OPTION_YES; //show设置为可以
    dbf_hton->create = dbf_create_handler; // 这是handler类，具体是对dbf类进行创建。
    dbf_hton->flags = HTON_CAN_RECREATE; //可以创建多个
    dbf_hton->system_database = dbf_system_database; //指定数据库
    dbf_hton->is_supported_system_table = dbf_is_supported_system_table; //支持系统表操作
    DBUG_RETURN(0);
}

/**
  @brief
  Dbf of simple lock controls. The "share" it creates is a
  structure we will pass to each dbf handler. Do you have to have
  one of these? Well, you have pieces that are used for locking, and
  they are needed to function.
*/

static Dbf_share *get_share(const char *table_name, TABLE *table)
{
    Dbf_share *tmp_share; //共享结构Dbf_share类
    char *tmp_name;
    uint length;
    length=(uint)strlen(table_name); //表名的长度
    DBUG_ENTER("ha_dbf::get_share()");
    mysql_mutex_lock(&dbf_mutex); //进行上锁
    /*
      If share is not present in the hash, create a new share and
      initialize its members.
    */
    //查找共享结构是否已经创建，用my_hash_search来查找，没创建的话要进行初始化创建
    if (!(tmp_share=(Dbf_share*)my_hash_search(&dbf_open_tables,
                                               (uchar*) table_name,
                                               length)))
    {
        //为tmp_share , tmp_name 分配长度为length+1的内存
        if (!my_multi_malloc(key_memory_dbf_share,
                             MYF(MY_WME | MY_ZEROFILL),
                             &tmp_share, sizeof(*tmp_share),
                             &tmp_name, length+1,
                             NullS))
        {
            //若分配失败，解锁并返回NULL
            mysql_mutex_unlock(&dbf_mutex);
            return NULL;
        }
        tmp_share->use_count=0; //使用次数
        tmp_share->table_name_length = length; //表名长度
        tmp_share->table_name=tmp_name; //表名
        strcpy(tmp_share->table_name, table_name);
        if (my_hash_insert(&dbf_open_tables, (uchar*) tmp_share)) //write a hash-key to the hash-index，要是失败则goto err
            goto err;
        thr_lock_init(&tmp_share->lock); //初始化tmp_share->lock
        mysql_mutex_init(key_mutex_Dbf_share_mutex,
                         &tmp_share->mutex, MY_MUTEX_INIT_FAST); //初始化tmp_share->mutex，赋成key_mutex_Dbf_share_mutex类型
    }
    tmp_share->use_count++;//使用次数+1
    mysql_mutex_unlock(&dbf_mutex);//解锁
    DBUG_RETURN(tmp_share);
    err:
    mysql_mutex_unlock(&dbf_mutex);
    if(tmp_share)
        my_free(tmp_share);
    DBUG_RETURN(NULL);
}

static handler *dbf_create_handler(handlerton *hton,
                                   TABLE_SHARE *table,
                                   MEM_ROOT *mem_root)
{
    return new (mem_root) ha_dbf(hton, table);
}

ha_dbf::ha_dbf(handlerton *hton, TABLE_SHARE *table_arg)
        : handler(hton, table_arg),
          current_position(0), //当前位置
          data_file(-1),//数据文件，初始化为-1
          number_records(-1),//记录有多少条数据
          number_del_records(-1), //记录删除了多少条
          header_size(sizeof(bool)+sizeof(int)+sizeof(int)), //头部长度
          record_header_size(sizeof(uchar)+sizeof(int)) //记录头部的长度
{
}

int ha_dbf::write_header(){
    DBUG_ENTER("ha_dbf::write_header");
    if(number_records!=-1){ //要是没被写过，也就是说当前是第一次写
        my_seek(data_file,0l,MY_SEEK_SET,MYF(0));//从0开始寻找文件位置
        my_write(data_file,(uchar*)&crashed,sizeof(bool),MYF(0)); //向文件写入creashed
        my_write(data_file,(uchar*)&number_records,sizeof(int),MYF(0)); //向文件写入number_records
        my_write(data_file,(uchar*)&number_del_records,sizeof(int),MYF(0)); //向文件写入number_del_records
    }
    DBUG_RETURN(0);
}

int ha_dbf::read_header(){
    int len;
    DBUG_ENTER("ha_dbf::read_header");
    if(number_records==-1){//要是没被读过，也就是说当前是第一次读
        my_seek(data_file,0L,MY_SEEK_SET,MYF(0)); //从0开始寻找文件位置
        my_read(data_file,(uchar*)&crashed,sizeof(bool),MYF(0)); //将文件中的uchar读取到creashed
        my_read(data_file,(uchar*)&len,sizeof(int),MYF(0)); //将文件中的下一个uchar读取到len
        memcpy(&number_records,&len,sizeof(int)); //number_records赋值成len
        my_read(data_file,(uchar*)&len,sizeof(int),MYF(0)); // 将文件中的下一个uchar读取到len
        memcpy(&number_del_records,&len,sizeof(int));//number_del_records赋值成len
    }else{
        my_seek(data_file,header_size,MY_SEEK_SET,MYF(0)); //否则只是定位文件，跳过头部信息，从header_size开始
    }
    DBUG_RETURN(0);
}

long long ha_dbf::cur_position(){
    long long pos;
    DBUG_ENTER("ha_dbf::cur_position");
    pos = my_seek(data_file,0L,MY_SEEK_CUR,MYF(0));//从0开始寻找文件位置
    if(pos==0){
        DBUG_RETURN(header_size); //跳过头部信息部分
    }
    DBUG_RETURN(pos);
}

int ha_dbf::readrow(uchar *buf,int length,long long position){
    int i;
    int rec_len;
    long long pos;
    uchar deleted = 2;
    DBUG_ENTER("ha_dbf::read_row");
    if(position<=0) position = header_size;
    pos = my_seek(data_file, position, MY_SEEK_SET, MYF(0)); //从当前position定位文件
    if(pos != -1L ){//定位到文件
        i = my_read(data_file, &deleted, sizeof(uchar), MYF(0)); //读出uchar数据到deleted
        if(deleted == 0){//要是delted为0证明读取成功
            i = my_read(data_file,(uchar*)&rec_len,sizeof(int),MYF(0));//读出uchar数据到rec_len变量
            i = my_read(data_file, buf , (length < rec_len)?length:rec_len, MYF(0)); //将rec_len和length进行比较，选择较小的一个进行buf数据读取
        }else if (i == 0){
            DBUG_RETURN(-1);
        }else {//否则，读取位置变成当前位置加上数据长度再加上头部长度，再次进行读取。
            DBUG_RETURN(readrow(buf,length,cur_position()+length+(record_header_size-sizeof(uchar))));
        }
    }else DBUG_RETURN(-1);
    DBUG_RETURN(0);
}

/**
  @brief
  If frm_error() is called then we will use this to determine
  the file extensions that exist for the storage engine. This is also
  used by the default rename_table and delete_table method in
  handler.cc.
  For engines that have two file name extentions (separate meta/index file
  and data file), the order of elements is relevant. First element of engine
  file name extentions array should be meta/index file extention. Second
  element - data file extention. This order is assumed by
  prepare_for_repair() when REPAIR TABLE ... USE_FRM is issued.
  @see
  rename_table method in handler.cc and
  delete_table method in handler.ccs
*/

static const char *ha_dbf_exts[] = {
        DBE_EXT,//数据文件名
        DBI_EXT,//索引文件名
        NullS};

const char **ha_dbf::bas_ext() const
{
    return ha_dbf_exts; //返回ha_dbf_exts数组
}

/*
  Following handler function provides access to
  system database specific to SE. This interface
  is optional, so every SE need not implement it.
*/
const char *ha_dbf_system_database = NULL;
const char *dbf_system_database()
{
    return ha_dbf_system_database;
}

/*
  List of all system tables specific to the SE.
  Array element would look like below,
     { "<database_name>", "<system table name>" },
  The last element MUST be,
     { (const char*)NULL, (const char*)NULL }
  This array is optional, so every SE need not implement it.
*/
static st_handler_tablename ha_dbf_system_tables[] = {
        {(const char *)NULL, (const char *)NULL}};

/**
  @brief Check if the given db.tablename is a system table for this SE.
  @param db                         Database name to check.
  @param table_name                 table name to check.
  @param is_sql_layer_system_table  if the supplied db.table_name is a SQL
                                    layer system table.
  @return
    @retval TRUE   Given db.table_name is supported system table.
    @retval FALSE  Given db.table_name is not a supported system table.
*/
static bool dbf_is_supported_system_table(const char *db,
                                          const char *table_name,
                                          bool is_sql_layer_system_table)
{
    st_handler_tablename *systab;

    // Does this SE support "ALL" SQL layer system tables ?
    if (is_sql_layer_system_table)
        return false;

    // Check if this is SE layer system tables
    systab = ha_dbf_system_tables;
    while (systab && systab->db)
    {
        if (systab->db == db &&
            strcmp(systab->tablename, table_name) == 0)
            return true;
        systab++;
    }

    return false;
}

/**
  @brief
  Used for opening tables. The name will be the name of the file.
  @details
  A table is opened when it needs to be opened; e.g. when a request comes in
  for a SELECT on the table (tables are not open and closed for each request,
  they are cached).
  Called from handler.cc by handler::ha_open(). The server opens all tables by
  calling ha_open() which then calls the handler specific open().
  @see
  handler::ha_open() in handler.cc
*/


int ha_dbf::open(const char *name, int mode, uint test_if_locked)
{
    DBUG_ENTER("ha_dbf::open");
    char name_buff[FN_REFLEN];
    if(!(share = get_share(name,table)))//获得共享结构
        DBUG_RETURN(1);
    char *path = fn_format(name_buff,name,"",DBE_EXT,MY_REPLACE_EXT|MY_UNPACK_FILENAME); //获得文件名
    data_file = my_open(path, O_RDWR | O_CREAT | O_BINARY | O_SHARE, MYF(0));//打开文件
    int flag = 0;
    if (data_file == -1)
        flag = 1;
    if(!flag){
        read_header(); //若打开文件成功，则读取文件头部信息
    }
    //初始化锁
    thr_lock_data_init(&share->lock, &lock, NULL);

    DBUG_RETURN(0);
}

/**
  @brief
  Closes a table.
  @details
  Called from sql_base.cc, sql_select.cc, and table.cc. In sql_select.cc it is
  only used to close up temporary tables or during the process where a
  temporary table is converted over to being a myisam table.
  For sql_base.cc look at close_data_tables().
  @see
  sql_base.cc, sql_select.cc and table.cc
*/

int ha_dbf::close(void)
{
    DBUG_ENTER("ha_dbf::close");
    DBUG_RETURN(0);
}

/**
  @brief
  write_row() inserts a row. No extra() hint is given currently if a bulk load
  is happening. buf() is a byte array of data. You can use the field
  information to extract the data from the native byte array type.
  @details
  Dbf of this would be:
  @code
  for (Field **field=table->field ; *field ; field++)
  {
    ...
  }
  @endcode
  See ha_tina.cc for an dbf of extracting all of the data as strings.
  ha_berekly.cc has an dbf of how to store it intact by "packing" it
  for ha_berkeley's own native storage type.
  See the note for update_row() on auto_increments. This case also applies to
  write_row().
  Called from item_sum.cc, item_sum.cc, sql_acl.cc, sql_insert.cc,
  sql_insert.cc, sql_select.cc, sql_table.cc, sql_udf.cc, and sql_update.cc.
  @see
  item_sum.cc, item_sum.cc, sql_acl.cc, sql_insert.cc,
  sql_insert.cc, sql_select.cc, sql_table.cc, sql_udf.cc and sql_update.cc
*/

int ha_dbf::write_row(uchar *buf)
{
    DBUG_ENTER("ha_dbf::write_row");
    /*
      Dbf of a successful write_row. We don't store the data
      anywhere; they are thrown away. A real implementation will
      probably need to do something with 'buf'. We report a success
      here, to pretend that the insert was successful.
    */
    ha_statistic_increment(&SSV::ha_write_count);//进行write的系统统计
    mysql_mutex_lock(&dbf_mutex);//上锁
    // buf , table->s->rec_buff_length
    int length = table->s->rec_buff_length; //获取数据项buf的长度
    long long pos;
    int i;
    int len;
    uchar deleted = 0;
    pos = my_seek(data_file, 0L, MY_SEEK_END, MYF(0)); //定位文件位置
    //先书写头部信息
    i = my_write(data_file, &deleted, sizeof(uchar), MYF(0)); //先写入deleted变量，用于readrow函数
    memcpy(&len,&length,sizeof(int)); //len赋值成length
    i = my_write(data_file, (uchar*)&len,sizeof(int),MYF(0)); //在写入len长度
    //再书写数据
    i = my_write(data_file, buf, length, MYF(0));
    if(i==-1) pos = i;
    else number_records++; //写成功，记录数加1
    if(pos){}
    mysql_mutex_unlock(&dbf_mutex);//解锁
    DBUG_RETURN(0);
}

/**
  @brief
  Yes, update_row() does what you expect, it updates a row. old_rec will have
  the previous row record in it, while new_rec will have the newest data in it.
  Keep in mind that the server can do updates based on ordering if an ORDER BY
  clause was used. Consecutive ordering is not guaranteed.
  @details
  Currently new_rec will not have an updated auto_increament record. You can
  do this for dbf by doing:
  @code
  if (table->next_number_field && record == table->record[0])
    update_auto_increment();
  @endcode
  Called from sql_select.cc, sql_acl.cc, sql_update.cc, and sql_insert.cc.
  @see
  sql_select.cc, sql_acl.cc, sql_update.cc and sql_insert.cc
*/
int ha_dbf::update_row(const uchar *old_rec, uchar *new_rec)
{

    DBUG_ENTER("ha_dbf::update_row");
    mysql_mutex_lock(&dbf_mutex);
    int length=table->s->rec_buff_length;
    longlong position =current_position-(length+record_header_size);
    longlong  pos;
    longlong cur_pos;
    uchar *cmp_rec;
    int len;
    uchar deleted=0;
    int i=-1;
    if(position==0)
        position=header_size; //移动 header
    pos=position;
    /*
        如果位置未知，通过一次读取一行来扫描记录，直到找到为止。
    */
    if(position==-1) //如果位置未知的情况
    {
        cmp_rec = (uchar *) my_malloc(key_memory_dbf_share, length, MYF(MY_ZEROFILL | MY_WME));
        pos = 0;

        /*
         * Note: my_seek() 返回记录位置，出错返回-1
        */
        cur_pos = my_seek(data_file, header_size, MY_SEEK_SET, MYF(0));
        /*
         * Note: read_row() 返回当前文件指针，若出错返回-1
         */
        while ((cur_pos != -1) && (pos != -1)) {
            pos = readrow(cmp_rec, length, cur_pos);
            if (memcmp(old_rec, cmp_rec, length) == 0) {
                pos = cur_pos;    //找到位置
                cur_pos = -1;     //停止循环
            } else if (pos != -1)   //移动到下条记录前
            {
                cur_pos = cur_pos + length + record_header_size;
            }
            my_free(cmp_rec);
        }
    }
    /*
     * 位置已知，修改行
     */
    if(pos!=-1)
    {
        /*
         * 写入删除的字节、行的长度和当前文件指针处的数据。
         */
        my_seek(data_file,pos,MY_SEEK_SET,MYF(0));
        i = my_write(data_file,&deleted,sizeof(uchar), MYF(0));
        memcpy(&len,&length,sizeof(int));
        i = my_write(data_file,(uchar*)&len,sizeof(int),MYF(0));
        pos = i;
        i = my_write(data_file, new_rec,length, MYF(0));
    }
    mysql_mutex_unlock(&dbf_mutex);
    DBUG_RETURN(0);
}

/**
  @brief
  This will delete a row. old_rec will contain a copy of the row to be deleted.
  The server will call this right after the current row has been called (from
  either a previous rnd_nexT() or index call).
  @details
  If you keep a pointer to the last row or can access a primary key it will
  make doing the deletion quite a bit easier. Keep in mind that the server does
  not guarantee consecutive deletions. ORDER BY clauses can be used.
  Called in sql_acl.cc and sql_udf.cc to manage internal table
  information.  Called in sql_delete.cc, sql_insert.cc, and
  sql_select.cc. In sql_select it is used for removing duplicates
  while in insert it is used for REPLACE calls.
  @see
  sql_acl.cc, sql_udf.cc, sql_delete.cc, sql_insert.cc and sql_select.cc
*/

int ha_dbf::delete_row(const uchar *old_rec)
{
    long long position;
    int length = table->s->rec_buff_length;
    int i =-1;
    long long pos;
    long long cur_pos;
    uchar *cmp_rec;
    uchar delected = 1;

    DBUG_ENTER("ha_dbf::delete_row");
    if(current_position>0)
        position = current_position - (length + record_header_size);
    else
        position=0;
    mysql_mutex_lock(&dbf_mutex);

    if(position == 0)
        position = header_size; //move past header
    pos=position;
    /*
     * 如果位置未知，通过一次读取一行来扫描记录，直到找到为止。
    */
    if(position==-1) //如果位置未知的情况
    {
        cmp_rec = (uchar *) my_malloc(key_memory_dbf_share, length, MYF(MY_ZEROFILL | MY_WME));
        pos = 0;

        /*
         * Note: my_seek() 返回位置，若出错返回-1
        */
        cur_pos = my_seek(data_file, header_size, MY_SEEK_SET, MYF(0));
        /*
         * Note: read_row() return 返回当前文件指针
         */
        while ((cur_pos != -1) && (pos != -1))
        {
            pos = readrow(cmp_rec, length, cur_pos);
            if (memcmp(old_rec, cmp_rec, length) == 0)
            {
                number_records--;
                number_del_records++;
                pos=cur_pos;
                cur_pos=-1;
            }
            else if (pos != -1)   //移动到下条记录前
            {
                cur_pos = cur_pos + length + record_header_size;
            }
            my_free(cmp_rec);
        }
    }
    /*
     * 位置已知，修改行
     */
    if(pos!=-1) {
        /*
         * 写入删除的字节、行的长度和当前文件指针处的数据。
         */
        pos=my_seek(data_file, pos, MY_SEEK_SET, MYF(0));
        i = my_write(data_file, &delected, sizeof(uchar), MYF(0));
        i=(i>1)?0:i;
    }

    mysql_mutex_unlock(&dbf_mutex);
    DBUG_RETURN(0);
}

/**
  @brief
  Positions an index cursor to the index specified in the handle. Fetches the
  row if available. If the key value is null, begin at the first key of the
  index.
*/

int ha_dbf::index_read_map(uchar *buf, const uchar *key,
                           key_part_map keypart_map MY_ATTRIBUTE((unused)),
                           enum ha_rkey_function find_flag
                           MY_ATTRIBUTE((unused)))
{
    int rc;
    DBUG_ENTER("ha_dbf::index_read");
    MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
    rc = HA_ERR_WRONG_COMMAND;
    MYSQL_INDEX_READ_ROW_DONE(rc);
    DBUG_RETURN(rc);
}

/**
  @brief
  Used to read forward through the index.
*/

int ha_dbf::index_next(uchar *buf)
{
    int rc;
    DBUG_ENTER("ha_dbf::index_next");
    MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
    rc = HA_ERR_WRONG_COMMAND;
    MYSQL_INDEX_READ_ROW_DONE(rc);
    DBUG_RETURN(rc);
}

/**
  @brief
  Used to read backwards through the index.
*/

int ha_dbf::index_prev(uchar *buf)
{
    int rc;
    DBUG_ENTER("ha_dbf::index_prev");
    MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
    rc = HA_ERR_WRONG_COMMAND;
    MYSQL_INDEX_READ_ROW_DONE(rc);
    DBUG_RETURN(rc);
}

/**
  @brief
  index_first() asks for the first key in the index.
  @details
  Called from opt_range.cc, opt_sum.cc, sql_handler.cc, and sql_select.cc.
  @see
  opt_range.cc, opt_sum.cc, sql_handler.cc and sql_select.cc
*/
int ha_dbf::index_first(uchar *buf)
{
    int rc;
    DBUG_ENTER("ha_dbf::index_first");
    MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
    rc = HA_ERR_WRONG_COMMAND;
    MYSQL_INDEX_READ_ROW_DONE(rc);
    DBUG_RETURN(rc);
}

/**
  @brief
  index_last() asks for the last key in the index.
  @details
  Called from opt_range.cc, opt_sum.cc, sql_handler.cc, and sql_select.cc.
  @see
  opt_range.cc, opt_sum.cc, sql_handler.cc and sql_select.cc
*/
int ha_dbf::index_last(uchar *buf)
{
    int rc;
    DBUG_ENTER("ha_dbf::index_last");
    MYSQL_INDEX_READ_ROW_START(table_share->db.str, table_share->table_name.str);
    rc = HA_ERR_WRONG_COMMAND;
    MYSQL_INDEX_READ_ROW_DONE(rc);
    DBUG_RETURN(rc);
}

/**
  @brief
  rnd_init() is called when the system wants the storage engine to do a table
  scan. See the dbf in the introduction at the top of this file to see when
  rnd_init() is called.
  @details
  Called from filesort.cc, records.cc, sql_handler.cc, sql_select.cc, sql_table.cc,
  and sql_update.cc.
  @see
  filesort.cc, records.cc, sql_handler.cc, sql_select.cc, sql_table.cc and sql_update.cc
*/
int ha_dbf::rnd_init(bool scan)
{
    DBUG_ENTER("ha_dbf::rnd_init");
    current_position=0;//当前位置
    stats.records= 0; //handler类中的记录个数变量
    ref_length = sizeof(long long); //数据项长度
    DBUG_RETURN(0);
}

int ha_dbf::rnd_end()
{
    DBUG_ENTER("ha_dbf::rnd_end");
    DBUG_RETURN(0);
}

/**
  @brief
  This is called for each row of the table scan. When you run out of records
  you should return HA_ERR_END_OF_FILE. Fill buff up with the row information.
  The Field structure for the table is the key to getting data into buf
  in a manner that will allow the server to understand it.
  @details
  Called from filesort.cc, records.cc, sql_handler.cc, sql_select.cc, sql_table.cc,
  and sql_update.cc.
  @see
  filesort.cc, records.cc, sql_handler.cc, sql_select.cc, sql_table.cc and sql_update.cc
*/
int ha_dbf::rnd_next(uchar *buf)
{
    int rc=-1;
    DBUG_ENTER("ha_dbf::rnd_next");
    ha_statistic_increment(&SSV::ha_read_rnd_next_count);//这条是用来进行统计分析rnd_next_count
    // buf table->s->rec_buff_length current_position
    rc = readrow(buf, table->s->rec_buff_length,current_position); //调用readrow进行数据读取
    if(rc!=-1) current_position = (off_t)cur_position(); //要是数据读取成功，那么调用cur_position给当前current_position进行更新
    else DBUG_RETURN(HA_ERR_END_OF_FILE);//否则，返回已经到文件末尾。
    stats.records++;//记录个数加1
    DBUG_RETURN(0);
}

/**
  @brief
  position() is called after each call to rnd_next() if the data needs
  to be ordered. You can do something like the following to store
  the position:
  @code
  my_store_ptr(ref, ref_length, current_position);
  @endcode
  @details
  The server uses ref to store data. ref_length in the above case is
  the size needed to store current_position. ref is just a byte array
  that the server will maintain. If you are using offsets to mark rows, then
  current_position should be the offset. If it is a primary key like in
  BDB, then it needs to be a primary key.
  Called from filesort.cc, sql_select.cc, sql_delete.cc, and sql_update.cc.
  @see
  filesort.cc, sql_select.cc, sql_delete.cc and sql_update.cc
*/
void ha_dbf::position(const uchar *record)
{
    DBUG_ENTER("ha_dbf::position");
    my_store_ptr(ref, ref_length, current_position);//存放指针
    DBUG_VOID_RETURN;
}

/**
  @brief
  This is like rnd_next, but you are given a position to use
  to determine the row. The position will be of the type that you stored in
  ref. You can use ha_get_ptr(pos,ref_length) to retrieve whatever key
  or position you saved when position() was called.
  @details
  Called from filesort.cc, records.cc, sql_insert.cc, sql_select.cc, and sql_update.cc.
  @see
  filesort.cc, records.cc, sql_insert.cc, sql_select.cc and sql_update.cc
*/
int ha_dbf::rnd_pos(uchar *buf, uchar *pos)
{
    DBUG_ENTER("ha_dbf::rnd_pos");
    ha_statistic_increment(&SSV::ha_read_rnd_next_count);//先进行系统统计
    current_position= (off_t)my_get_ptr(pos,ref_length);//引用变量和检索长度
    //buf , current_position , -1
    readrow(buf, current_position, -1);//再进行数据读取
    DBUG_RETURN(0);
}

/**
  @brief
  ::info() is used to return information to the optimizer. See my_base.h for
  the complete description.
  @details
  Currently this table handler doesn't implement most of the fields really needed.
  SHOW also makes use of this data.
  You will probably want to have the following in your code:
  @code
  if (records < 2)
    records = 2;
  @endcode
  The reason is that the server will optimize for cases of only a single
  record. If, in a table scan, you don't know the number of records, it
  will probably be better to set records to two so you can return as many
  records as you need. Along with records, a few more variables you may wish
  to set are:
    records
    deleted
    data_file_length
    index_file_length
    delete_length
    check_time
  Take a look at the public variables in handler.h for more information.
  Called in filesort.cc, ha_heap.cc, item_sum.cc, opt_sum.cc, sql_delete.cc,
  sql_delete.cc, sql_derived.cc, sql_select.cc, sql_select.cc, sql_select.cc,
  sql_select.cc, sql_select.cc, sql_show.cc, sql_show.cc, sql_show.cc, sql_show.cc,
  sql_table.cc, sql_union.cc, and sql_update.cc.
  @see
  filesort.cc, ha_heap.cc, item_sum.cc, opt_sum.cc, sql_delete.cc, sql_delete.cc,
  sql_derived.cc, sql_select.cc, sql_select.cc, sql_select.cc, sql_select.cc,
  sql_select.cc, sql_show.cc, sql_show.cc, sql_show.cc, sql_show.cc, sql_table.cc,
  sql_union.cc and sql_update.cc
*/
int ha_dbf::info(uint flag)
{
    DBUG_ENTER("ha_dbf::info");
    if(stats.records<2) stats.records=2;//欺骗优化器
    DBUG_RETURN(0);
}

/**
  @brief
  extra() is called whenever the server wishes to send a hint to
  the storage engine. The myisam engine implements the most hints.
  ha_innodb.cc has the most exhaustive list of these hints.
    @see
  ha_innodb.cc
*/
int ha_dbf::extra(enum ha_extra_function operation)
{
    DBUG_ENTER("ha_dbf::extra");
    DBUG_RETURN(0);
}

/**
  @brief
  Used to delete all rows in a table, including cases of truncate and cases where
  the optimizer realizes that all rows will be removed as a result of an SQL statement.
  @details
  Called from item_sum.cc by Item_func_group_concat::clear(),
  Item_sum_count_distinct::clear(), and Item_func_group_concat::clear().
  Called from sql_delete.cc by mysql_delete().
  Called from sql_select.cc by JOIN::reinit().
  Called from sql_union.cc by st_select_lex_unit::exec().
  @see
  Item_func_group_concat::clear(), Item_sum_count_distinct::clear() and
  Item_func_group_concat::clear() in item_sum.cc;
  mysql_delete() in sql_delete.cc;
  JOIN::reinit() in sql_select.cc and
  st_select_lex_unit::exec() in sql_union.cc.
*/
int ha_dbf::delete_all_rows()
{
    DBUG_ENTER("ha_dbf::delete_all_rows");
    mysql_mutex_lock(&dbf_mutex);
    if(data_file!=-1)
    {
        my_chsize(data_file,0,0, MYF(MY_WME));
        write_header();
    }
    mysql_mutex_unlock(&dbf_mutex);
    DBUG_RETURN(0);
}

/**
  @brief
  Used for handler specific truncate table.  The table is locked in
  exclusive mode and handler is responsible for reseting the auto-
  increment counter.
  @details
  Called from Truncate_statement::handler_truncate.
  Not used if the handlerton supports HTON_CAN_RECREATE, unless this
  engine can be used as a partition. In this case, it is invoked when
  a particular partition is to be truncated.
  @see
  Truncate_statement in sql_truncate.cc
  Remarks in handler::truncate.
*/
int ha_dbf::truncate()
{
    DBUG_ENTER("ha_dbf::truncate");
    DBUG_RETURN(HA_ERR_WRONG_COMMAND);
}

/**
  @brief
  This create a lock on the table. If you are implementing a storage engine
  that can handle transacations look at ha_berkely.cc to see how you will
  want to go about doing this. Otherwise you should consider calling flock()
  here. Hint: Read the section "locking functions for mysql" in lock.cc to understand
  this.
  @details
  Called from lock.cc by lock_external() and unlock_external(). Also called
  from sql_table.cc by copy_data_between_tables().
  @see
  lock.cc by lock_external() and unlock_external() in lock.cc;
  the section "locking functions for mysql" in lock.cc;
  copy_data_between_tables() in sql_table.cc.
*/
int ha_dbf::external_lock(THD *thd, int lock_type)
{
    DBUG_ENTER("ha_dbf::external_lock");
    DBUG_RETURN(0);
}

/**
  @brief
  The idea with handler::store_lock() is: The statement decides which locks
  should be needed for the table. For updates/deletes/inserts we get WRITE
  locks, for SELECT... we get read locks.
  @details
  Before adding the lock into the table lock handler (see thr_lock.c),
  mysqld calls store lock with the requested locks. Store lock can now
  modify a write lock to a read lock (or some other lock), ignore the
  lock (if we don't want to use MySQL table locks at all), or add locks
  for many tables (like we do when we are using a MERGE handler).
  Berkeley DB, for dbf, changes all WRITE locks to TL_WRITE_ALLOW_WRITE
  (which signals that we are doing WRITES, but are still allowing other
  readers and writers).
  When releasing locks, store_lock() is also called. In this case one
  usually doesn't have to do anything.
  In some exceptional cases MySQL may send a request for a TL_IGNORE;
  This means that we are requesting the same lock as last time and this
  should also be ignored. (This may happen when someone does a flush
  table when we have opened a part of the tables, in which case mysqld
  closes and reopens the tables and tries to get the same locks at last
  time). In the future we will probably try to remove this.
  Called from lock.cc by get_lock_data().
  @note
  In this method one should NEVER rely on table->in_use, it may, in fact,
  refer to a different thread! (this happens if get_lock_data() is called
  from mysql_lock_abort_for_thread() function)
  @see
  get_lock_data() in lock.cc
*/
THR_LOCK_DATA **ha_dbf::store_lock(THD *thd,
                                   THR_LOCK_DATA **to,
                                   enum thr_lock_type lock_type)
{
    if (lock_type != TL_IGNORE && lock.type == TL_UNLOCK)
        lock.type = lock_type;
    *to++ = &lock;
    return to;
}

/**
  @brief
  Used to delete a table. By the time delete_table() has been called all
  opened references to this table will have been closed (and your globally
  shared references released). The variable name will just be the name of
  the table. You will need to remove any files you have created at this point.
  @details
  If you do not implement this, the default delete_table() is called from
  handler.cc and it will delete all files with the file extensions returned
  by bas_ext().
  Called from handler.cc by delete_table and ha_create_table(). Only used
  during create if the table_flag HA_DROP_BEFORE_CREATE was specified for
  the storage engine.
  @see
  delete_table and ha_create_table() in handler.cc
*/
int ha_dbf::delete_table(const char *name)
{
    DBUG_ENTER("ha_dbf::delete_table");
    /* This is not implemented but we want someone to be able that it works. */
    char name_buff[FN_REFLEN];
    if(!(share=get_share(name,table)))//获得共享结构
        DBUG_RETURN(1);
    mysql_mutex_lock(&dbf_mutex);//设置锁
    if(data_file!=-1){
        my_close(data_file,MYF(0));//先把文件关了
        data_file=-1;
    }
    char*path = fn_format(name_buff, name, "", DBE_EXT, MY_REPLACE_EXT | MY_UNPACK_FILENAME);//获得文件名
    my_delete(path,MYF(0));//调用api删除文件
    mysql_mutex_unlock(&dbf_mutex);//解锁
    DBUG_RETURN(0);
}

/**
  @brief
  Renames a table from one name to another via an alter table call.
  @details
  If you do not implement this, the default ./() is called from
  handler.cc and it will delete all files with the file extensions returned
  by bas_ext().
  Called from sql_table.cc by mysql_rename_table().
  @see
  mysql_rename_table() in sql_table.cc
*/
int ha_dbf::rename_table(const char *from, const char *to)
{
    DBUG_ENTER("ha_dbf::rename_table ");
    char data_from[FN_REFLEN];
    char data_to[FN_REFLEN];
    if(!(share=get_share(from,table)))//获得共享结构
        DBUG_RETURN(1);
    mysql_mutex_lock(&dbf_mutex);//上锁
    if(data_file!=-1){
        my_close(data_file,MYF(0)); //先关文件
        data_file=-1;
    }
    //对文件数据进行复制，调用api my_copy
    my_copy(fn_format(data_from, from, "", DBE_EXT, MY_REPLACE_EXT | MY_UNPACK_FILENAME), 
            fn_format(data_to, to, "", DBE_EXT, MY_REPLACE_EXT | MY_UNPACK_FILENAME),
            MYF(0));
    int flag = 0;
    //打开新文件
    data_file = my_open(data_to, O_RDWR | O_CREAT | O_BINARY | O_SHARE, MYF(0));
    if(data_file==-1){
        flag = 1;
    }
    //读取新文件的头部信息
    if(!flag){
        read_header();
    }
    mysql_mutex_unlock(&dbf_mutex);//解锁
    my_delete(data_from,MYF(0));//删除掉旧文件
    DBUG_RETURN(0);
}

/**
  @brief
  Given a starting key and an ending key, estimate the number of rows that
  will exist between the two keys.
  @details
  end_key may be empty, in which case determine if start_key matches any rows.
  Called from opt_range.cc by check_quick_keys().
  @see
  check_quick_keys() in opt_range.cc
*/
ha_rows ha_dbf::records_in_range(uint inx, key_range *min_key,
                                 key_range *max_key)
{
    DBUG_ENTER("ha_dbf::records_in_range");
    DBUG_RETURN(10); // low number to force index usage
}

/**
  @brief
  create() is called to create a database. The variable name will have the name
  of the table.
  @details
  When create() is called you do not need to worry about
  opening the table. Also, the .frm file will have already been
  created so adjusting create_info is not necessary. You can overwrite
  the .frm file at this point if you wish to change the table
  definition, but there are no methods currently provided for doing
  so.
  Called from handle.cc by ha_create_table().
  @see
  ha_create_table() in handle.cc
*/

int ha_dbf::create(const char *name, TABLE *table_arg,
                   HA_CREATE_INFO *create_info)
{
    char name_buff[FN_REFLEN];
    DBUG_ENTER("ha_dbf::create");
    if(!(share=get_share(name,table))) //获得共享结构
        DBUG_RETURN(1);
    //用fn_format读取出文件名
    char *path = fn_format(name_buff,name,"",DBE_EXT,MY_REPLACE_EXT|MY_UNPACK_FILENAME); 
    //打开文件，使用api my_open 
    data_file = my_open(path, O_RDWR | O_CREAT | O_BINARY | O_SHARE, MYF(0));
    int flag = 0;
    //要是打开文件失败，那么flag置1
    if (data_file == -1)
        flag = 1;
    if(!flag) read_header(); //flag不为1，说明打开文件成功，读取文件头部信息
    number_records = 0;//初始化数量记录为0
    number_del_records = 0;//初始化删除数量记录为0
    crashed = false; //初始化崩溃参数为false
    write_header();//写入头部信息
    if(flag) DBUG_RETURN(-1); //要是flag=1，说明打开文件失败，返回-1
    if(data_file!=-1){ //要是有文件打开了，那么创建过程的最后要把他关闭掉。
        my_close(data_file,MYF(0));
        data_file = -1;
    }
    DBUG_RETURN(0);
}

struct st_mysql_storage_engine dbf_storage_engine =
        {MYSQL_HANDLERTON_INTERFACE_VERSION};

static ulong srv_enum_var = 0;
static ulong srv_ulong_var = 0;
static double srv_double_var = 0;

const char *enum_var_names[] =
        {
                "e1", "e2", NullS};

TYPELIB enum_var_typelib =
        {
                array_elements(enum_var_names) - 1, "enum_var_typelib",
                enum_var_names, NULL};

static MYSQL_SYSVAR_ENUM(
        enum_var,                       // name
        srv_enum_var,                   // varname
        PLUGIN_VAR_RQCMDARG,            // opt
        "Sample ENUM system variable.", // comment
        NULL,                           // check
        NULL,                           // update
        0,                              // def
        &enum_var_typelib);             // typelib

static MYSQL_SYSVAR_ULONG(
        ulong_var,
        srv_ulong_var,
        PLUGIN_VAR_RQCMDARG,
        "0..1000",
        NULL,
        NULL,
        8,
        0,
        1000,
        0);

static MYSQL_SYSVAR_DOUBLE(
        double_var,
        srv_double_var,
        PLUGIN_VAR_RQCMDARG,
        "0.500000..1000.500000",
        NULL,
        NULL,
        8.5,
        0.5,
        1000.5,
        0); // reserved always 0

static MYSQL_THDVAR_DOUBLE(
        double_thdvar,
        PLUGIN_VAR_RQCMDARG,
        "0.500000..1000.500000",
        NULL,
        NULL,
        8.5,
        0.5,
        1000.5,
        0);

static struct st_mysql_sys_var *dbf_system_variables[] = {
        MYSQL_SYSVAR(enum_var),
        MYSQL_SYSVAR(ulong_var),
        MYSQL_SYSVAR(double_var),
        MYSQL_SYSVAR(double_thdvar),
        NULL};

// this is an dbf of SHOW_FUNC and of my_snprintf() service
static int show_func_dbf(MYSQL_THD thd, struct st_mysql_show_var *var,
                         char *buf)
{
    var->type = SHOW_CHAR;
    var->value = buf; // it's of SHOW_VAR_FUNC_BUFF_SIZE bytes
    my_snprintf(buf, SHOW_VAR_FUNC_BUFF_SIZE,
                "enum_var is %lu, ulong_var is %lu, "
                "double_var is %f, %.6b", // %b is a MySQL extension
                srv_enum_var, srv_ulong_var, srv_double_var, "really");
    return 0;
}

struct dbf_vars_t
{
    ulong var1;
    double var2;
    char var3[64];
    bool var4;
    bool var5;
    ulong var6;
};

dbf_vars_t dbf_vars = {100, 20.01, "three hundred", true, 0, 8250};

static st_mysql_show_var show_status_dbf[] =
        {
                {"var1", (char *)&dbf_vars.var1, SHOW_LONG, SHOW_SCOPE_GLOBAL},
                {"var2", (char *)&dbf_vars.var2, SHOW_DOUBLE, SHOW_SCOPE_GLOBAL},
                {0, 0, SHOW_UNDEF, SHOW_SCOPE_UNDEF} // null terminator required
        };

static struct st_mysql_show_var show_array_dbf[] =
        {
                {"array", (char *)show_status_dbf, SHOW_ARRAY, SHOW_SCOPE_GLOBAL},
                {"var3", (char *)&dbf_vars.var3, SHOW_CHAR, SHOW_SCOPE_GLOBAL},
                {"var4", (char *)&dbf_vars.var4, SHOW_BOOL, SHOW_SCOPE_GLOBAL},
                {0, 0, SHOW_UNDEF, SHOW_SCOPE_UNDEF}};

static struct st_mysql_show_var func_status[] =
        {
                {"dbf_func_dbf", (char *)show_func_dbf, SHOW_FUNC, SHOW_SCOPE_GLOBAL},
                {"dbf_status_var5", (char *)&dbf_vars.var5, SHOW_BOOL, SHOW_SCOPE_GLOBAL},
                {"dbf_status_var6", (char *)&dbf_vars.var6, SHOW_LONG, SHOW_SCOPE_GLOBAL},
                {"dbf_status", (char *)show_array_dbf, SHOW_ARRAY, SHOW_SCOPE_GLOBAL},
                {0, 0, SHOW_UNDEF, SHOW_SCOPE_UNDEF}};

mysql_declare_plugin(dbf){
                                 MYSQL_STORAGE_ENGINE_PLUGIN,
                                 &dbf_storage_engine,
                                 "DBF",
                                 "Brian Aker, MySQL AB",
                                 "Dbf storage engine",
                                 PLUGIN_LICENSE_GPL,
                                 dbf_init_func, /* Plugin Init */
                                 NULL,          /* Plugin Deinit */
                                 0x0001 /* 0.1 */,
                                 func_status,          /* status variables */
                                 dbf_system_variables, /* system variables */
                                 NULL,                 /* config options */
                                 0,                    /* flags */
                         } mysql_declare_plugin_end;
