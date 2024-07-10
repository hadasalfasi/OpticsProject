﻿using AutoMapper;
using DAL.Dtos;
using Models.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DAL.Profiles
{
    internal class CustomerProfiles:Profile
    {

        public CustomerProfiles()
        {
                CreateMap<CustomerDto, Customer>();
                CreateMap<Customer, CustomerDto>();
        }
    }
}
