﻿namespace IdentityIntPrimaryKey.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class testnewcolumninusertable : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.User", "LatineName", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.User", "LatineName");
        }
    }
}
