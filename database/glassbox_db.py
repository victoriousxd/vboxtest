import psycopg2

class DBConnection:

    #   This sets up the connection to the database used to store process information
    #   There are also optional host and port inputs to psycopg2.connect() but I wasn't
    #   sure if support for those would be necessary.  As the table is set up now, it is
    #   more memory intensive in favor of preserving speed.

    #   set_connection takes in a string for each parameter  The password field is not
    #   required, but the dbname and user are.

    def __init__(self, table_name):
        self.connection = None
        self.cursor = None
        self.table_name = table_name

    def set_connection(self, dbname=None, user=None, password=None):
        if dbname is None or user is None:
            raise ValueError("Either dbname or user is unspecified")
        if password is None:
            self.connection = psycopg2.connect(dbname=dbname, user=user)
        else:
            self.connection = psycopg2.connect(dbname=dbname, user=user, password=password)
        self.cursor = self.connection.cursor();

    #   Destroy a connection

    def destroy_connection(self):
        if self.connection is not None:
            self.connection.close()
        self.connection = None
        self.cursor = None

    #   Reset a connection

    def reset_connection(self, dbname=None, user=None, password=None):
        self.destroy_connection()
        self.set_connection(dbname=dbname, user=user, password=password)

    #   This drops the syscalls table

    def drop_syscalls(self):
        if self.table_name is None:
            raise ValueError("No table name specified")
        if self.cursor is None:
            raise ValueError("No database connection")
        query = f"drop table {self.table_name};"
        self.cursor.execute(query)
        self.connection.commit()

    #   Creates the syscalls table.  Only do this if the table doesn't exist

    def create_syscalls(self):
        if self.cursor is None:
            raise ValueError("No database connection")
        query = f"""
        create table {self.table_name}(sequence varchar primary key, network varchar, success bool, syscall smallint, exit smallint, ppid int, pid int, auid int, uid int, gid int, euid int, suid int, fsuid int, egid int, sgid int, fsgid int, A0 bigint, A1 bigint, A2 bigint, A3 bigint, ts varchar, comm varchar, exe varchar, subj varchar, ky varchar, tty varchar)
        """
        self.cursor.execute(query)
        self.connection.commit()

    #   This adds a syscall to the table.  It takes in 26 parameters.
    def add_syscall(self, sequence, network , success , syscall , exit , ppid , pid , auid , uid , gid , euid , suid , fsuid , egid , sgid , fsgid , A0 , A1 , A2 , A3 , ts , comm, exe, subj, ky, tty):
        if self.cursor is None:
            raise ValueError("No database connection")
        query = f"""
        insert into {self.table_name}(sequence, network , success , syscall , exit , ppid , pid , auid , uid , gid , euid , suid , fsuid , egid , sgid , fsgid , A0 , A1 , A2 , A3 , ts , comm, exe, subj, ky, tty)
            values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """
        values = (sequence, network , success , syscall , exit , ppid , pid , auid , uid , gid , euid , suid , fsuid , egid , sgid , fsgid , A0 , A1 , A2 , A3 , ts , comm, exe, subj, ky, tty)
        self.cursor.execute(query, values)
        self.connection.commit()


    #   Get a syscall based on sequence.  Since sequence is a primary key, it should only return one syscall.

    def get_syscall(self, sequence):
        if self.cursor is None:
            raise ValueError("No database connection")
        query = f"""
        select * from {self.table_name}
        where sequence = %s;
        """
        self.cursor.execute(query, (sequence,))
        return self.cursor.fetchone()

   #    This function returns a list of syscalls based on batch_Size, exe, and/or pid.  

    def get_batch_syscalls(self, batch_size=-1, exe=None, pid=None):
        result = []
        query = ""
        values = ()
        if (exe is None and pid is None):
            query = f"""
            select * from {self.table_name}
            """
        elif (exe is not None and pid is not None):
            query = f"""
            select * from {self.table_name}
            where exe = %s and pid = %s;
            """
            values = (exe, pid)
        elif (exe is not None):
            query = f"""
            select * from {self.table_name}
            where exe = %s;
            """
            values = (exe,)
        else:
            query = f"""
            select * from {self.table_name}
            where pid = %s;
            """
            values = (pid,)
        self.cursor.execute(query, values)
        if (batch_size < 0):
            return self.cursor.fetchall()
        else:
            yield self.cursor.fetchmany(batch_size)
